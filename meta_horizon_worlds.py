#“Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement”;

from volatility3.framework import interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import TreeGrid
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, vadinfo
import re


class MetaHorizonWorlds(interfaces.plugins.PluginInterface):

    _required_framework_version = (2, 7, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel64"],
            )
        ]

    TOKEN_REGEX = re.compile(rb"Bearer\\s+[A-Za-z0-9\\-\\._~\\+/=]+")
    CHAT_REGEX = re.compile(rb"(chat|say|message)[^\\x00]{5,200}", re.I)

    def _generator(self):
        kernel = self.config["kernel"]

        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=kernel,
        ):
            name = utility.array_to_string(proc.ImageFileName)
            if "horizon" not in name.lower():
                continue

            try:
                layer_name = proc.add_process_layer()
                layer = self.context.layers[layer_name]
            except exceptions.InvalidAddressException:
                continue

            for vad in vadinfo.VadInfo.list_vads(proc):
                try:
                    start = vad.get_start()
                    size = min(vad.get_size(), 5 * 1024 * 1024)
                    data = layer.read(start, size, pad=True)
                except exceptions.InvalidAddressException:
                    continue

                for m in self.TOKEN_REGEX.finditer(data):
                    yield 0, (proc.UniqueProcessId, name, "TOKEN", hex(start), m.group().decode(errors="ignore"))

                for m in self.CHAT_REGEX.finditer(data):
                    yield 0, (proc.UniqueProcessId, name, "CHAT", hex(start), m.group().decode(errors="ignore"))

    def run(self):
        return TreeGrid(
            [("PID", int), ("Process", str), ("Type", str), ("VAD", str), ("Data", str)],
            self._generator(),
        )
