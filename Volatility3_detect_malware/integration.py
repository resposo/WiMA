from typing import Iterable
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.windows import pslist, psscan, dlllist
from .thrdscan import ThrdScan
from .sessions import Sessions
from datetime import datetime
import logging
import traceback
import tkinter as tk
from tkinter import ttk
import logging
from .PRDSS import CombinedPRDSIAT
from volatility3.framework import constants

# 로깅 설정
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)




class HiddenProcessesGUI(plugins.PluginInterface):

    _required_framework_version = (2, 5, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> Iterable[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name='primary',
                description='Memory layer for the kernel',
                architectures=['Intel32', 'Intel64']
            ),
            requirements.SymbolTableRequirement(
                name="nt_symbols", 
                description="Windows kernel symbols"
            ),
            requirements.BooleanRequirement(
                name="privilege", 
                description="Check privileges from systemprivileges_pid.txt(First, run privilegesmodify)",
                optional=True
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            )
        ]

    def _get_privilege_pids(self):
        try:
            with open("systemprivileges_pid.txt", "r") as f:
                lines = f.readlines()
                privileges = {}
                for line in lines:
                    parts = line.strip().split(", ")
                    pid = int(parts[0].split(":")[1].strip())
                    priv_data = {}
                    for priv in parts[1:]:
                        priv_num = int(priv.split(":")[1].split()[0])
                        attributes = priv.split("[")[1].split("]")[0].split(",") if priv.split("[")[1].split("]")[0].strip() else []
                        priv_data[priv_num] = attributes
                    privileges[pid] = priv_data
                return privileges
        except FileNotFoundError:
            raise Exception("Please run privilegesmodify first and then use --privilege")
        except Exception as e:
            logger.debug(f"Failed to read systemprivileges_pid.txt: {e}")
            return {}

    def analyze_privileges(self, privilege_data):
        if all(not privilege_data.get(num) for num in [7, 20, 29]):
            return "Low"
        if all(privilege_data.get(num, []) == ["Present", "Enabled", "Default"] for num in [7, 20, 29]) or privilege_data.get(20, []) == ["Present", "Enabled", "Default"]:
            return "High"
        if any(any(val in privilege_data.get(num, []) for val in ["Present", "Enabled", "Default"]) for num in [7, 20, 29]):
            return "Medium"

    def _generator(self):
        psscan_plugin = psscan.PsScan.scan_processes(
            self.context, 
            self.config['primary'], 
            self.config['nt_symbols']
        )

        threadscan_plugin = ThrdScan.scan_threads(
            self.context, 
            self.config['primary'], 
            self.config['nt_symbols']
        )

        pslist_plugin = pslist.PsList.list_processes(
            self.context, 
            self.config['primary'], 
            self.config['nt_symbols'],
        )

        Sessions_plugin_Username = pslist.PsList.list_processes(
            self.context, 
            self.config['primary'], 
            self.config['nt_symbols']
        )

        pslist_processes = {
            p.UniqueProcessId: (
                p.ImageFileName.cast("string", max_length=p.ImageFileName.vol.count, errors="replace"), 
                p.InheritedFromUniqueProcessId
            ) for p in pslist_plugin
        }

        sessions_data = {}
        for proc in Sessions_plugin_Username:
            full_user = Sessions.extract_user_info(proc)
            sessions_data[proc.UniqueProcessId] = full_user

        psscan_processes = {
            p.UniqueProcessId: (
                p.ImageFileName.cast("string", max_length=p.ImageFileName.vol.count, errors="replace"), 
                p.InheritedFromUniqueProcessId, 
                p.get_create_time(),
                p.get_exit_time()
            ) for p in psscan_plugin
        }

        all_process_names = [p[0] for p in pslist_processes.values()] + [p[0] for p in psscan_processes.values()]
        process_name_width = max(len(name) for name in all_process_names)

        thread_processes = [thread.Cid.UniqueProcess for thread in threadscan_plugin]

        privilege_data = self._get_privilege_pids()

        combined_processes = {}
        for pid, (name, ppid) in pslist_processes.items():
            create_time_str = psscan_processes[pid][2].strftime('%Y-%m-%d %H:%M:%S') if pid in psscan_processes and isinstance(psscan_processes[pid][2], datetime) else 'N/A'
            exit_time_str = psscan_processes[pid][3].strftime('%Y-%m-%d %H:%M:%S') if pid in psscan_processes and isinstance(psscan_processes[pid][3], datetime) else 'N/A'

            combined_processes[pid] = {
                'name': name,
                'ppid': ppid,
                'in_pslist': True,
                'in_psscan': pid in psscan_processes,
                'create_time': create_time_str,
                'exit_time': exit_time_str
            }

        for pid, (name, ppid, create_time, exit_time) in psscan_processes.items():
            create_time_str = create_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(create_time, datetime) else 'N/A'
            exit_time_str = exit_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(exit_time, datetime) else 'N/A'

            if pid not in combined_processes:
                combined_processes[pid] = {
                    'name': name,
                    'ppid': ppid,
                    'in_pslist': False,
                    'in_psscan': True,
                    'create_time': create_time_str,
                    'exit_time': exit_time_str
                }

        # 사용자가 입력한 PID를 가져옴
        specific_pid = self.config.get('pid', None)
        
        for pid, process_info in combined_processes.items():
            # specific_pid가 설정되어 있고, 현재의 PID가 그것과 다르면 skip
            if specific_pid and pid not in specific_pid:
                continue
            
            full_user = sessions_data.get(pid, 'N/A')
            padded_process_name = process_info['name'].ljust(process_name_width)
            privilege_status = "-"
            if self.config.get('privilege', False):
                privilege_status = "N/A"  # 옵션을 주었지만, 데이터가 없는 경우 "N/A"로 설정
                if pid in privilege_data:
                    privilege_status = self.analyze_privileges(privilege_data[pid])
            
            yield (0, (pid, 
                    padded_process_name, 
                    process_info['ppid'], 
                    process_info['in_pslist'], 
                    process_info['in_psscan'], 
                    pid in thread_processes, 
                    process_info['create_time'], 
                    process_info['exit_time'], 
                    full_user, 
                    privilege_status))
    def run(self):
        logger.info("This plugin runs with a GUI. CLI output is not available.")
        data = []
        for output in self._generator():
            data.append(output[1])
        self.open_gui(data)
        return renderers.TreeGrid([
            ("Info", str),
        ], self._inform_gui_only())

    def _inform_gui_only(self):
        yield (0, ("Shut down the plug-in. Goodbye :) -[DFV]Resposo",))

    def open_gui(self, data):
        root = tk.Tk()
        root.title("Hidden Processes")
        tree = ttk.Treeview(root, columns=("PID", "ProcessName", "PPID", "Pslist", "Psscan", "Thdscan", "CreateTime", "ExitTime", "UserName", "ProcessPrivilege"), show='headings')
        for col in ("PID", "ProcessName", "PPID", "Pslist", "Psscan", "Thdscan", "CreateTime", "ExitTime", "UserName", "ProcessPrivilege"):
            tree.heading(col, text=col)
            tree.column(col, width=100, anchor="w")

        for item in data:
            tree.insert('', 'end', values=item)

        # 항목 더블클릭 이벤트 처리바인딩 추가
        tree.bind("<Double-1>", lambda event, t=tree: self.on_item_double_click(event, t))

        tree.pack(expand=True, fill='both')
        root.mainloop()
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set the database path here
        self.db_path = r"C:\Users\user\Desktop\메모리\volatility3-2.4.1\PRDS.db"

    def on_item_double_click(self, event, tree):
        item_id = tree.selection()[0]
        item = tree.item(item_id, "values")
        pid = int(item[0])

        try:
            detail_window = tk.Toplevel()
            detail_window.title(f"Details for PID {pid}")

            config_path = self.config_path + constants.BANG + "CombinedPRDSIAT"
            self.context.config[config_path + ".primary"] = self.config["primary"]
            self.context.config[config_path + ".nt_symbols"] = self.config["nt_symbols"]

            # CombinedPRDSIAT 인스턴스 초기화 및 실행
            combined_prdsiat = CombinedPRDSIAT(
                context=self.context,
                config_path=config_path,
                progress_callback=None
            )

            # 구성 검증 및 실행
            combined_prdsiat.validate_config()
            for _, details in combined_prdsiat._generator():
                # 결과 처리 로직...
                pass

        except Exception as e:
            logger.error(f"Error during plugin execution: {e}")
            tk.Label(detail_window, text=f"Error: {e}", font=('Helvetica', 10)).pack()