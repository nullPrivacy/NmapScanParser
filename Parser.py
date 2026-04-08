#James McKinley
#NmapParser Poject v0.1.0
from dataclasses import dataclass
import subprocess 
import xml.etree.ElementTree as ET

######Constants
MAX_ATTEMPTS = 3
NMAP_COMMAND = 'nmap'
NMAP_ARG1 = '-sV'
NMAP_ARG2 = '-oX'


######Helper Classes
#Class decorator requied to use syntax
@dataclass(frozen=True)     
class ParserResult:
    protocol:str
    port_id: int
    state:str
    reason:str
    reason_ttl:str
    name:str
    method:str
    conf:str


class InputHandler:
    def get_input_ip(self) -> str:
        usr_ip = input(f"Enter the IP you would like to scan: ")
        if not usr_ip or not isinstance(usr_ip, str):
            raise ValueError("No IP address entered")
        return usr_ip

    def get_input_file(self) -> str:
        usr_filename = input(f"Enter the FILE NAME you would like to scan: ")
        if not usr_filename or not isinstance(usr_filename,str):
            raise ValueError("No file name entered")
        return usr_filename 


######Main Classes
class Scanner:
    def __init__(self, usr_ip: str,usr_filename: str):
        self.__scanner_ip = usr_ip
        self.__scanner_filename = usr_filename

    def scan_xml(self)-> int:
        result = subprocess.run([NMAP_COMMAND, NMAP_ARG1, NMAP_ARG2,
                                 f"{self.__scanner_filename}.xml", 
                                 f"{self.__scanner_ip}"], 
                                capture_output = True, text=True)
        if result.returncode == 0:
            if "(0 hosts up)" in result.stdout:
                raise ValueError("No Hosts Available")
            return 0 
        #else (Failure) dont check output, dont invoke parser.
        return 1
        
            
class Parser:
    def __init__(self, usr_filename: str):
        self.__parser_filename = usr_filename
        self.__parser_list = []

    def parse_xml_port(self) -> list:      
        tree = ET.parse(f"{self.__parser_filename}.xml")
        root = tree.getroot()
        for port in root.iter('port'):
            result = ParserResult( 
                protocol = port.get('protocol'),
                port_id = port.get('portid'),
                state = port.find('state').get('state') 
                    if port.find('state') is not None else "unkown",
                reason = port.find('state').get('reason')
                    if port.find('state') is not None else "unkown",
                reason_ttl = port.find('state').get('reason_ttl')
                    if port.find('state') is not None else "unkown",
                name = port.find('service').get('name')
                    if port.find('service') is not None else "unkown",
                method = port.find('service').get('method')
                    if port.find('service') is not None else "unkown",
                conf = port.find('service').get('conf')
                    if port.find('service') is not None else "unkown"
            )
            self.__parser_list.append(result)
        return self.__parser_list

class Reporter:
    def __init__(self, usr_filename: str, report_to_write: list):
        self.__reporter_filename = usr_filename
        self.__reporter_list = []
        self.__reporter_list = report_to_write

    #Add return value 
    def write_xml_txt(self):
        with open(f"{self.__reporter_filename}.txt", "w") as file:
            for reports in self.__reporter_list:
                file.write(f"Protocol: {reports.protocol}\n")
                file.write(f"Port ID: {reports.port_id}\n")
                file.write(f"State: {reports.state}\n")
                file.write(f"Reason: {reports.reason}\n")
                file.write(f"Reason_ttl: {reports.reason_ttl}\n")
                file.write(f"Name: {reports.name}\n")
                file.write(f"Method: {reports.method}\n")
                file.write(f"Conf: {reports.conf}\n")
                file.write(f"---\n")

class Manager:
    def __init__(self):
        self.__report = []
        self.__usr_ip = None
        self.__usr_filename = None

    #Need better return
    def run_scan_port(self) -> bool:
            in_handler = InputHandler()

            try:
                self.__usr_ip = in_handler.get_input_ip()
                self.__usr_filename = in_handler.get_input_file()
                scanner = Scanner(self.__usr_ip, self.__usr_filename)
                if scanner.scan_xml() is True:
                    parser = Parser(self.__usr_filename)
                    self.__report = parser.parse_xml_port()
                    reporter = Reporter(self.__usr_filename, self.__report)
                    reporter.write_xml_txt()
                    return True
                else:
                    return False
            except ValueError as e:
                print(f"Unable to generate report: {e}")
#####MAIN
def main():
    manager = Manager()
    manager.run_scan_port()

if __name__ == "__main__":
    main()

