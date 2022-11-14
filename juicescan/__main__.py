import cProfile

from juicescan.juicescan import ManualPortAnalyzer, ShodanPortAnalyzer
from juicescan.parser import CommandInfo, Parser

if __name__ == "__main__":
    parser = Parser()
    command_info: CommandInfo = parser.validate()
    manual_analyzer = ManualPortAnalyzer(command_info)
    shodan_analyzer = ShodanPortAnalyzer(command_info)
    manual_analyzer.scan()
