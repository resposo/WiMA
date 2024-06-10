from volatility3.framework import constants, interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
import logging

class AddrTranslate(plugins.PluginInterface):
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)
    _log = logging.getLogger(__name__)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name='primary', 
                description='Memory layer for the kernel', 
                architectures=['Intel32', 'Intel64']
            ),
            requirements.SymbolTableRequirement(
                name='nt_symbols', 
                description='Windows kernel symbols'
            ),
            requirements.IntRequirement(
                name='virtaddr', 
                description='Virtual address to translate', 
                optional=False
            )
        ]

    def _translate_vtop(self, layer, offset):
        try:
            return layer.translate(offset)
        except exceptions.InvalidAddressException as e:
            self._log.error(f"Invalid address {offset}: {str(e)}")
        except Exception as e:
            self._log.error(f"Error translating address {offset}: {str(e)}")
        return None

    def run(self):
        layer_name = self.config['primary']
        virt_addr = self.config.get('virtaddr', None)
        layer = self.context.layers[layer_name]

        phys_addr = self._translate_vtop(layer, virt_addr)

        if phys_addr is None:
            return renderers.TreeGrid(
                [("Virtual Address", str), ("Physical Address", str)],
                [(str(virt_addr), "Unable to translate - possible invalid address or page fault")]
            )
        
        return renderers.TreeGrid(
            [("Virtual Address", str), ("Physical Address", str)],
            [(str(virt_addr), str(phys_addr))]
        )

