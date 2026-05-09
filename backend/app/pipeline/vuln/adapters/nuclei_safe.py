"""nuclei_safe — stub for M-Vuln-2.

Real nuclei integration with safe/non-intrusive templates is planned for M-Vuln-3.
This stub allows the DAG profile to include nuclei_safe without failing.
"""


class NucleiSafeStage:
    name = "nuclei_safe"
    source_tool = "nuclei"
    depends_on: list[str] = []
    weight = 60
    optional = True
    intrusive_required = False

    async def execute_vuln(self, ctx) -> list:
        # Stub: real nuclei integration in M-Vuln-3
        return []
