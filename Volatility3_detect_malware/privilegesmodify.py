import json
import logging
import os
from collections import OrderedDict
from typing import List
from volatility3.framework.configuration import requirements
from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows import psscan

vollog = logging.getLogger(__name__)

class ModPrivs(interfaces.plugins.PluginInterface):
    """Lists process token privileges and saves the results to a txt file (systemprivileges_pid.txt)"""
    
    _version = (1, 2, 0)
    _required_framework_version = (2, 0, 0)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.priv_list = OrderedDict()
        self.output_file = "systemprivileges_pid.txt"

        for plugin_dir in constants.PLUGINS_PATH:
            sids_json_file_name = os.path.join(plugin_dir, os.path.join("windows", "only_privileges.json"))
            if os.path.exists(sids_json_file_name):
                break
        else:
            raise RuntimeError("The only_privileges.json file is missing from your plugin directory")

        with open(sids_json_file_name, "r") as file_handle:
            temp_json = json.load(file_handle)["privileges"]
            self.privilege_info = {int(priv_num): temp_json[priv_num] for priv_num in temp_json}

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]),
            requirements.ListRequirement(name="pid", description="Filter on specific process IDs", element_type=int, optional=True),
            requirements.PluginRequirement(name="pslist", plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.PluginRequirement(name="psscan", plugin=psscan.PsScan, version=(2, 0, 0))
        ]

    @staticmethod
    def collect_privileges(process_token, privilege_info):
        privilege_dict = {}
        for value, present, enabled, default in process_token.privileges():
            if not privilege_info.get(int(value)):
                continue
            attributes = []
            if present:
                attributes.append("Present")
            if enabled:
                attributes.append("Enabled")
            if default:
                attributes.append("Default")
            privilege_dict[int(value)] = attributes
        return privilege_dict

    def add_pid_to_priv_list(self, pid, detected_privileges):
        """Adds a PID to the priv_list instance variable along with detected privileges."""
        self.priv_list[pid] = detected_privileges

    def format_detected_privileges(self, privilege_dict):
        """Formats the detected privileges as per the desired string format."""
        privilege_strings = []
        for priv_num, attributes in privilege_dict.items():
            priv_string = f"Privileges : {priv_num} [{','.join(attributes)}]"
            privilege_strings.append(priv_string)
        return ", ".join(privilege_strings)

    def _generator(self, procs):
        for task in procs:
            try:
                process_token = task.Token.dereference().cast("_TOKEN")
                privilege_dict = ModPrivs.collect_privileges(process_token, self.privilege_info)
                formatted_privileges = self.format_detected_privileges(privilege_dict)
                self.add_pid_to_priv_list(task.UniqueProcessId, formatted_privileges)
            except exceptions.InvalidAddressException:
                continue
            yield (0, [int(task.UniqueProcessId), formatted_privileges])

    def save_pids_to_txt(self):
        """Save PID and detected privileges to txt file."""
        with open(self.output_file, 'w') as f:
            for pid, detected_privileges in self.priv_list.items():
                f.write(f"PID: {pid}, {detected_privileges}\n")

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]   
        
        pslist_procs = list(pslist.PsList.list_processes(self.context, kernel.layer_name, kernel.symbol_table_name, filter_func=filter_func))
        psscan_procs = list(psscan.PsScan.scan_processes(self.context, kernel.layer_name, kernel.symbol_table_name, filter_func=filter_func))

        # Combine unique processes from both pslist and psscan based on UniqueProcessId
        proc_dict = {proc.UniqueProcessId: proc for proc in (pslist_procs + psscan_procs)}
        combined_procs = list(proc_dict.values())

        results = list(self._generator(combined_procs))
        self.save_pids_to_txt()

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Detected Privileges", str),
            ],
            results
        )
