from volatility3.framework import interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import TreeGrid
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, vadinfo
import re


class EAChromium(interfaces.plugins.PluginInterface):
    """
    Volatility 3 plugin to extract potential credentials, tokens, and chat strings
    from EA background services and Chromium WebView processes associated with
    the EA App on Windows 11.

    This plugin targets processes known to host OAuth tokens and chat data,
    scanning their memory regions (VADs) for patterns matching typical EA tokens
    and chat-related strings.

    Attributes:
        TOKEN_REGEX (re.Pattern): Regex to identify typical OAuth Bearer tokens.
        CHAT_REGEX (re.Pattern): Regex to identify chat-like strings in memory.
        TARGET_PROCESSES (list[str]): List of default process names to scan.

    Usage:
        vol -f memory.raw windows.mhworlds_ea_chromium.MHWorldsEAChromium
    """

    _required_framework_version = (2, 7, 0)

    @classmethod
    def get_requirements(cls):
        """
        Defines plugin configuration requirements.

        Returns:
            list: List of requirements for this plugin, including kernel module,
                  optional PID list, and optional process name filter.
        """
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="Process ID(s) to scan (optional)",
                element_type=int,
                optional=True,
            ),
            requirements.StringRequirement(
                name="process_name",
                description="Process name(s) to scan (optional, comma-separated)",
                default="",
                optional=True,
            ),
        ]

    # Regex to match common OAuth Bearer tokens and EA token prefixes
    TOKEN_REGEX = re.compile(
        rb"(Bearer|EAAB|EAAI|EAAG)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE
    )

    # Regex to match chat-related strings (case-insensitive)
    CHAT_REGEX = re.compile(rb"(chat|say|message|whisper|room)[^\x00]{5,200}", re.IGNORECASE)

    # Default target processes known to contain relevant data
    TARGET_PROCESSES = [
        "eabackgroundservice",
        "eadesktopservice",
        "msedgewebview2",
        "eawebview",
    ]

    def _generator(self):
        """
        Generator function that yields found artifacts matching token or chat patterns.

        Iterates over target processes, reads readable memory regions (VADs),
        applies regex scanning, and yields findings.

        Yields:
            tuple: A tuple suitable for TreeGrid containing
                - Process ID (int)
                - Process name (str)
                - Artifact type ("TOKEN" or "CHAT") (str)
                - Virtual address of the memory region (str)
                - Extracted string data (str)
        """
        kernel = self.config["kernel"]
        target_pids = self.config.get("pid", [])
        user_process_names = [
            n.strip().lower()
            for n in self.config.get("process_name", "").split(",")
            if n.strip()
        ]

        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=kernel,
        ):
            pname = utility.array_to_string(proc.ImageFileName).lower()

            # Filter by PID if specified
            if target_pids and proc.UniqueProcessId not in target_pids:
                continue

            # Filter by user-specified process names if provided
            if user_process_names:
                if not any(u in pname for u in user_process_names):
                    continue
            else:
                # Otherwise, filter by default target process names
                if not any(t in pname for t in self.TARGET_PROCESSES):
                    continue

            try:
                # Obtain the process memory layer
                layer = self.context.layers[proc.add_process_layer()]
            except exceptions.InvalidAddressException:
                # Skip processes with invalid or inaccessible memory layers
                continue

            # Iterate over the process's Virtual Address Descriptors (VADs)
            for vad in vadinfo.VadInfo.list_vads(proc):
                try:
                    start = vad.get_start()
                    # Limit read size to 10MB to balance performance and completeness
                    size = min(vad.get_size(), 10 * 1024 * 1024)
                    data = layer.read(start, size, pad=True)
                except exceptions.InvalidAddressException:
                    # Skip unreadable memory regions
                    continue

                # Search for token patterns in the memory region
                for match in self.TOKEN_REGEX.finditer(data):
                    yield 0, (
                        proc.UniqueProcessId,
                        pname,
                        "TOKEN",
                        hex(start),
                        match.group().decode(errors="ignore"),
                    )

                # Search for chat-related strings in the memory region
                for match in self.CHAT_REGEX.finditer(data):
                    yield 0, (
                        proc.UniqueProcessId,
                        pname,
                        "CHAT",
                        hex(start),
                        match.group().decode(errors="ignore"),
                    )

    def run(self):
        """
        Plugin entry point called by Volatility.

        Returns:
            TreeGrid: Rendered grid of artifacts found by _generator.
        """
        return TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Type", str),
                ("VAD Start", str),
                ("Extracted Data", str),
            ],
            self._generator(),
        )
