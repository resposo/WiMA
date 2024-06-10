import logging
import hashlib
import io
import os
import pefile
import sqlite3
from volatility3.framework import exceptions, interfaces, renderers, configuration
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, ldrmodules
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.framework import constants
from volatility3.plugins.windows import CombinedPRDSIAT
# gui
import tkinter as tk
from tkinter import ttk, messagebox
import csv
from tkinter import filedialog

# 로거 설정
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealPRDS(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    def __init__(self, context, config_path, progress_callback=None):
        super().__init__(context, config_path, progress_callback=progress_callback)
        self.db_path = self.config.get('database', None)
        self.use_database = bool(self.db_path)  # 데이터베이스 사용 여부 설정
        if self.use_database:
            self.initialize_db(self.db_path)  # 데이터베이스 경로가 제공되었을 때만 초기화

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]),
            requirements.ListRequirement(name="pid", element_type=int, description="Process IDs to include", optional=True),
            requirements.IntRequirement(name="search", description="Search for specific PID", optional=True),
            requirements.BooleanRequirement(name="gui", description="Use GUI for output", default=False, optional=True),
            requirements.StringRequirement(name="database", description="Path to the SQLite database for storing results", optional=True, default=None),
        ]

    @classmethod
    def list_processes(cls, context, layer_name, symbol_table, filter_func=lambda _: False):
        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        list_entry = ntkrnlmp.object(object_type="_LIST_ENTRY", offset=ps_aph_offset)
        reloff = ntkrnlmp.get_type("_EPROCESS").relative_child_offset("ActiveProcessLinks")

        eproc = ntkrnlmp.object(object_type="_EPROCESS", offset=list_entry.vol.offset - reloff, absolute=True)
        for proc in eproc.ActiveProcessLinks:
            if not filter_func(proc):
                yield proc

    def find_process_name_by_pid(self, context, kernel, pid):
        target_proc = next(filter(lambda p: p.UniqueProcessId == pid, self.list_processes(context, kernel.layer_name, kernel.symbol_table_name)), None)
        if target_proc is not None:
            try:
                return utility.array_to_string(target_proc.ImageFileName)
            except exceptions.InvalidAddressException as e:
                logger.exception(f"Error reading ImageFileName for PID {pid}: {e}")
                return "Error reading ImageFileName"
        return "N/A"

    def find_parent_process_name(self, context, kernel, proc):
        parent_pid = proc.InheritedFromUniqueProcessId
        return self.find_process_name_by_pid(context, kernel, parent_pid)

    def find_exe_path(self, proc):
        try:
            for module in proc.load_order_modules():
                dll_name = module.FullDllName.get_string()
                return dll_name
        except exceptions.InvalidAddressException:
            return "Error reading Executable Path"
        return "N/A"

    def get_dll_details(self, context, proc, kernel):
        dll_names = []
        try:
            proc_layer_name = proc.add_process_layer()
            peb = context.object(kernel.symbol_table_name + constants.BANG + "_PEB", layer_name=proc_layer_name, offset=proc.Peb)
            pe_table_name = intermed.IntermediateSymbolTable.create(context, kernel.symbol_table_name, "windows", "pe", class_types=pe.class_types)
            pe_data = io.BytesIO()
            dos_header = context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER", offset=peb.ImageBaseAddress, layer_name=proc_layer_name)

            if dos_header.e_magic != 0x5A4D:
                return []

            for offset, data in dos_header.reconstruct():
                pe_data.seek(offset)
                pe_data.write(data)

            pe_obj = pefile.PE(data=pe_data.getvalue(), fast_load=True)
            pe_obj.parse_data_directories([pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])

            if hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', 'ignore').lower().replace('\\', '/') if entry.dll else "Unknown"
                    dll_names.append(dll_name)

        except exceptions.PagedInvalidAddressException as e:
            return []  # 페이지 폴트 오류 발생시 빈 리스트 반환
        except (ValueError, exceptions.InvalidAddressException) as e:
            return []

        return dll_names

    def calculate_sha256(self, process_name, exe_path, parent_name, dll_names):
        # 경로의 역슬래시를 슬래시로 변환
        dll_names = [dll_name.replace('\\', '/') for dll_name in dll_names]
        
        # DLL 이름 리스트 정렬
        sorted_dll_names = sorted(dll_names)
        
        # 로깅 및 해시 계산은 기존과 동일
        logger.debug(f"Calculating SHA-256 for Process: {process_name}, Executable Path: {exe_path}, Parent Process: {parent_name}, DLLs: {sorted_dll_names}")
        hash_input = ';'.join([process_name, exe_path, parent_name] + sorted_dll_names)
        return hashlib.sha256(hash_input.encode()).hexdigest()

    def check_sha256_in_db(self, sha256, db_path):
        """ 주어진 SHA256 값이 데이터베이스에 존재하는지 확인하는 함수 """
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM analysis_results WHERE sha256 = ?", (sha256,))

        result = cursor.fetchone()[0] > 0
        conn.close()
        return result
    
    def get_ldrmodules_mapped_paths(self, context, kernel):
        mapped_paths = {}
        for proc in pslist.PsList.list_processes(context, kernel.layer_name, kernel.symbol_table_name):
            proc_layer_name = proc.add_process_layer()
            proc_symbol_table_name = proc.get_symbol_table_name()

            ldr_output = ldrmodules.LdrModules(context=context, config_path=self.config_path)
            ldr_output.config['pid'] = proc.UniqueProcessId
            ldr_output.config['layer_name'] = proc_layer_name
            ldr_output.config['symbol_table'] = proc_symbol_table_name

            try:
                for row in ldr_output._generator([proc]):
                    _, output = row
                    pid, _, _, _, _, _, mapped_path = output
                    if pid not in mapped_paths:
                        mapped_paths[pid] = []
                    if isinstance(mapped_path, str):
                        # '\\'를 '/'로 교체하여 경로 표시를 통일
                        standardized_path = mapped_path.replace('\\', '/')
                        mapped_paths[pid].append(standardized_path)
            except Exception as e:
                logger.error(f"Error running LdrModules for PID {proc.UniqueProcessId}: {e}")
                if proc.UniqueProcessId not in mapped_paths:
                    mapped_paths[proc.UniqueProcessId] = []

        return mapped_paths

    # 데이터베이스 초기화 및 테이블 생성
    def initialize_db(self, db_path):
        logger.debug(f"Attempting to connect to the database at {db_path}")
        if not os.path.exists(os.path.dirname(db_path)):
            logger.error(f"Directory does not exist: {os.path.dirname(db_path)}")
        if not os.path.isfile(db_path) and not os.access(os.path.dirname(db_path), os.W_OK):
            logger.error(f"No write permission to the directory: {os.path.dirname(db_path)}")
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pname TEXT,
                    exe_path TEXT,
                    ppname TEXT,
                    dll_list TEXT,
                    sha256 TEXT
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sha256 ON analysis_results (sha256)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_pname ON analysis_results (pname)')
            conn.commit()
            conn.close()
            logger.debug("Database initialized successfully")
        except Exception as e:
            logger.exception(f"Failed to initialize the database: {e}")

    # 데이터 삽입 함수
    def insert_analysis_result(self, db_path, pname, exe_path, ppname, dll_list, sha256):
        # Ensure the DLL list is sorted and uses forward slashes before insertion
        sorted_and_standardized_dll_list = ";".join(sorted(dll_list.replace('\\', '/').split(';')))
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO analysis_results (pname, exe_path, ppname, dll_list, sha256)
            VALUES (?, ?, ?, ?, ?)
        ''', (pname, exe_path, ppname, sorted_and_standardized_dll_list, sha256))
        conn.commit()
        conn.close()

    def find_dll_differences(self, analyzed_dlls, stored_dlls):
        # 경로를 소문자로 변환하고 슬래시로 통일
        analyzed_lower = {dll.lower().replace('\\', '/') for dll in analyzed_dlls}
        stored_lower = set()
        for dlls in stored_dlls:
            stored_lower.update({dll.lower().replace('\\', '/') for dll in dlls.split(';')})
        
        # 로깅으로 목록을 출력
        logger.debug(f"Standardized analyzed DLLs: {analyzed_lower}")
        logger.debug(f"Standardized stored DLLs: {stored_lower}")

        # 데이터베이스에 없는 DLL
        new_in_analyzed = sorted(analyzed_lower - stored_lower)

        # 불일치하는 항목을 로깅
        logger.debug(f"Different DLLs: {new_in_analyzed}")

        return new_in_analyzed, []
    
    def get_all_dlls_for_process_name(self, db_path, pname):
        """데이터베이스에서 주어진 프로세스 이름과 일치하는 모든 항목의 DLL 목록을 반환"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        dll_lists = []
        try:
            cursor.execute("SELECT dll_list FROM analysis_results WHERE pname = ?", (pname,))
            rows = cursor.fetchall()
            for row in rows:
                dll_lists.append(row[0])  # 각 행의 dll_list를 추가
        except sqlite3.Error as e:
            logger.error(f"Database query failed for {pname}: {e}")
        finally:
            conn.close()
        return dll_lists
    
    def check_process_name_in_db(self, pname, db_path):
        """주어진 프로세스 이름이 데이터베이스에 존재하는지 확인하는 함수"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM analysis_results WHERE pname = ?", (pname,))
        result = cursor.fetchone()[0] > 0
        conn.close()
        return result

    def _generator(self):
        if self.use_database:
            db_path = self.db_path
        else:
            db_path = r"C:\Users\user\Desktop\메모리\volatility3-2.4.1\PRDS.db"
            self.initialize_db(db_path)

        search_pid = self.config.get("search", None)
        kernel = self.context.modules[self.config["kernel"]]
        ldrmodules_mapped_paths = self.get_ldrmodules_mapped_paths(self.context, kernel)
        procs = self.list_processes(self.context, kernel.layer_name, kernel.symbol_table_name)
        sha256_to_pids = {}
        proc_details = {}
        processed_pids = set()

        for proc in procs:
            try:
                pid = proc.UniqueProcessId
                process_name = utility.array_to_string(proc.ImageFileName)
                parent_name = self.find_parent_process_name(self.context, kernel, proc)
                exe_path = self.find_exe_path(proc)
                dll_names = ldrmodules_mapped_paths.get(pid, [])
                dll_list_str = ";".join(sorted(dll_names))
                sha256_hash = self.calculate_sha256(process_name, exe_path, parent_name, dll_names)
                pname_exists_in_db = self.check_process_name_in_db(process_name, db_path)

                is_detected = "Unknown"  # 기본값은 "Unknown"
                if pname_exists_in_db:
                    is_detected = "TRUE" if self.check_sha256_in_db(sha256_hash, db_path) else "FALSE"

                all_stored_dlls = self.get_all_dlls_for_process_name(db_path, process_name)
                combined_stored_dlls = set()
                for dll_list in all_stored_dlls:
                    for dll in dll_list.split(';'):
                        combined_stored_dlls.add(dll.lower().replace('\\', '/'))

                new_in_analyzed, _ = self.find_dll_differences(dll_names, combined_stored_dlls)
                dll_diff_str = ";".join(new_in_analyzed) if new_in_analyzed else ""

                same_pid_list = [str(other_pid) for other_pid in sha256_to_pids.get(sha256_hash, []) if other_pid != pid]

                if self.use_database:
                    self.insert_analysis_result(db_path, process_name, exe_path, parent_name, dll_list_str, sha256_hash)

                proc_details[pid] = (
                    process_name, exe_path, parent_name, sha256_hash, is_detected, 
                    dll_list_str, dll_diff_str, ",".join(same_pid_list)
                )

                if sha256_hash not in sha256_to_pids:
                    sha256_to_pids[sha256_hash] = []
                sha256_to_pids[sha256_hash].append(pid)

            except (exceptions.PagedInvalidAddressException, exceptions.InvalidAddressException) as e:
                logger.error(f"Error processing process {pid}: {e}")

        for pid, details in proc_details.items():
            if pid in processed_pids:
                continue
            # 모든 프로세스 출력
            processed_pids.add(pid)
            yield (0, (pid, details[0], details[1], details[2], details[3], details[4], details[7], details[5], details[6]))

    def get_stored_dlls_by_alternate_key(self, db_path, pname, exe_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            query = """
            SELECT id, dll_list FROM analysis_results 
            WHERE pname = ? AND (exe_path = ? OR exe_path IS NULL OR exe_path = '' OR exe_path = 'N/A')
            """
            cursor.execute(query, (pname, exe_path if exe_path != "N/A" else ""))

            result = cursor.fetchone()
            if result:
                db_id, stored_dlls_str = result  # 올바르게 id와 dll_list를 분리하여 할당
                stored_dlls = stored_dlls_str.lower().replace('\\', '/').split(';') if stored_dlls_str else []
                return db_id, stored_dlls  # 문자열 처리에 대한 오류를 방지
            return None, []  # 결과가 없는 경우 None과 빈 리스트 반환
        except sqlite3.Error as e:
            logger.error(f"Database query failed for {pname} with exe_path {exe_path}: {e}")
            return None, []
        finally:
            conn.close()

    def run(self):
        if self.config.get('gui', False):
            return self.run_gui()
        else:
            return self.run_text()

    def run_text(self):
        filtered_pids = []
        for _, details in self._generator():
            # Detect 값이 FALSE 또는 Unknown인 경우만 처리
            if details[5] in ["FALSE", "Unknown"]:
                filtered_pids.append(str(details[0]))  # PID 저장

        # 필터링된 PID를 임시 파일에 저장
        if os.path.exists("filtered_pids.txt"):
            response = input("The file 'filtered_pids.txt' already exists. Do you want to overwrite it? (y/n): ")
            write_mode = 'w' if response.lower() == 'y' else 'a'
        else:
            write_mode = 'w'

        with open("filtered_pids.txt", write_mode) as f:
            f.write("\n".join(filtered_pids) + "\n")

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process_Name", str),
                ("Executable_Path", str),
                ("Parent_Process_Name", str),
                ("SHA-256", str),
                ("Detect", str),
                ("Same PID", str),
                ("DLL(ldrmodules)", str),
                ("Different_dll", str),
            ],
            self._generator()
        )

    def run_gui(self):
        root = tk.Tk()
        app = CombinedPRDSIAT_GUI(root, self)
        root.mainloop()

        # GUI 이벤트 루프 종료 후, 텍스트 파일 저장
        filtered_pids = []
        for _, details in self._generator():
            filtered_pids.append(str(details[0]))  # PID 저장

        # 필터링된 PID를 임시 파일에 저장
        if os.path.exists("filtered_pids.txt"):
            result = messagebox.askquestion("Overwrite or Append", "The file 'filtered_pids.txt' already exists. Do you want to overwrite it?", icon='warning')
            if result == 'yes':
                write_mode = 'w'
            else:
                write_mode = 'a'
        else:
            write_mode = 'w'

        with open("filtered_pids.txt", write_mode) as f:
            f.write("\n".join(filtered_pids) + "\n")

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process_Name", str),
                ("Executable_Path", str),
                ("Parent_Process_Name", str),
                ("SHA-256", str),
                ("Detect", str),
                ("Same PID", str),
                ("DLL(ldrmodules)", str),
                ("Different_dll", str),
            ],
            self._generator()
        )

    def generate_text_output(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process_Name", str),
                ("Executable_Path", str),
                ("Parent_Process_Name", str),
                ("SHA-256", str),
                ("Detect", str),
                ("Same PID", str),
                ("DLL(ldrmodules)",str),
                ("Different_dll", str),
            ],
            self._generator()
        )

# GUI methods
class CombinedPRDSIAT_GUI:
    def __init__(self, master, plugin):
        self.master = master
        self.plugin = plugin
        master.title("[DFV] Analysis Tool")
        
        # 정렬 옵션 선택을 위한 Combobox 추가
        self.label_filter = tk.Label(master, text="Filter by Detect:")
        self.label_filter.grid(row=0, column=0, sticky="w")
        self.filter_combobox = ttk.Combobox(master, values=["All", "True", "False", "Unknown"])
        self.filter_combobox.grid(row=0, column=1, sticky="ew")
        self.filter_combobox.set("All")  # 기본값 설정

        # 검색 버튼
        self.search_button = tk.Button(master, text="Search", command=self.run_search)
        self.search_button.grid(row=0, column=2, sticky="ew")

        # 결과 표시를 위한 Treeview와 스크롤바
        self.tree = ttk.Treeview(master, columns=("PID", "Process_Name", "Executable_Path", "Parent_Process_Name", "SHA-256", "Detect", "Same PID", "DLL(ldrmodules)", "Different_dll"), show='headings')
        self.vscroll = ttk.Scrollbar(master, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.vscroll.set)
        self.vscroll.grid(row=2, column=9, sticky="ns")
        self.tree.grid(row=2, column=0, columnspan=9, sticky="nsew")

        # 수평 스크롤바 설정
        self.hscroll = ttk.Scrollbar(master, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=self.hscroll.set)
        self.hscroll.grid(row=3, column=0, columnspan=9, sticky="ew")

        # Treeview 컬럼 설정
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(col, width=100)  # 컬럼 너비 설정
        
        # CSV로 내보내기 버튼
        self.export_button = tk.Button(master, text="Export to CSV", command=self.export_to_csv)
        self.export_button.grid(row=4, column=0, columnspan=9, sticky="ew")

        # 창 크기 조절 가능성 설정
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(2, weight=1)

    def run_search(self):
        # Treeview 내용 클리어
        for i in self.tree.get_children():
            self.tree.delete(i)

        # 플러그인의 _generator 메소드를 호출하여 결과를 Treeview에 채움
        for item in self.plugin._generator():
            self.tree.insert('', 'end', values=item[1])

    def export_to_csv(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        )
        if not filepath:
            return  # 사용자가 파일 저장을 취소한 경우

        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([col.title() for col in self.tree["columns"]])
            for item in self.tree.get_children():
                row = self.tree.item(item, "values")
                csvwriter.writerow(row)

        messagebox.showinfo("Export Successful", f"Data exported successfully to {filepath}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CombinedPRDSIAT_GUI(root, CombinedPRDSIAT())
    root.mainloop()
