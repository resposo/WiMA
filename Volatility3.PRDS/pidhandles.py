from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.windows import handles, pslist
from typing import Iterable

class ModifiedPidHandles(plugins.PluginInterface):
    """Lists handles opened by csrss.exe processes"""

    _required_framework_version = (2, 5, 0)
    _version = (1, 0, 0)

    #@classmethod
    #def get_requirements(cls):
    #    return [
    #        requirements.TranslationLayerRequirement(name='primary',
    #                                                 description='Memory layer for the kernel',
    #                                                 architectures=["Intel32", "Intel64"]),
    #        requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
    #        requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
    #    ]
    
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
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _generator(self):
        # Find csrss PIDs
        csrss_pids = []
        #pslist_plugin = pslist.PsList(context=self.context, config_path=self._config_path)
        pslist_plugin = pslist.PsList.list_processes(
            self.context, 
            self.config['primary'], 
            self.config['nt_symbols']
        )

        for proc in pslist_plugin():
            if proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors='replace') == "csrss.exe":
                csrss_pids.append(proc.UniqueProcessId)

        # Generate the handles for each csrss PID
        for proc in csrss_pids:
            handle_plugin = handles.Handles(context=self.context, config_path=self._config_path)
            handle_plugin.set_config("pid", csrss_pids)

            for handle in handle_plugin.handles():
                yield (0, (handle.UniqueProcessId,
                           handle.ObjectType,
                           handle.GrantedAccess,
                           handle.HandleValue))

    def run(self):
        return renderers.TreeGrid([("UniqueProcessId", int),
                                   ("ObjectType", str),
                                   ("GrantedAccess", int),
                                   ("HandleValue", int)],
                                  self._generator())
