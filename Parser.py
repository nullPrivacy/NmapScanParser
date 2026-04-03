#James McKinley
#NmapParser Poject
from dataclasses import dataclass
import subprocess 
import xml.etree.ElementTree as ET

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
    ##Need to find better solution for return condition
    def get_input_ip(self) -> str:
        usr_ip = input(f"Enter the IP you would like to scan: ")
        return usr_ip

    def get_input_file(self) -> str:
        usr_filename = input(f"Enter the FILE NAME you would like to scan: ")
        return usr_filename 

######Main Classes
class Scanner:
    def __init__(self, usr_ip: str,usr_filename: str):
        self.__scanner_ip = usr_ip
        self.__scanner_filename = usr_filename

    #Need process for invalid ip or filename response
    def scan_xml(self):
        subprocess.run(["nmap", "-sV", "-oX", f"{self.__scanner_filename}.xml", f"{self.__scanner_ip}"])
            
class Parser:
    def __init__(self, usr_filename: str):
        self.__parser_filename = usr_filename
        self.__parser_list = []

    #Thinking of renaming to better fit the nmap argument description "-sV"
    def parse_xml_port(self) -> list:      
        tree = ET.parse(f"{self.__parser_filename}.xml")
        root = tree.getroot()

        for port in root.iter('port'):
            result = ParserResult( 
                protocol = port.get('protocol'),#if port.find('protocol') is not None else "unkown",
                port_id = port.get('portid'),#if port.find('portid') is not None else "unkown",
                state = port.find('state').get('state')if port.find('state') is not None else "unkown",
                reason = port.find('state').get('reason')if port.find('state') is not None else "unkown",
                reason_ttl = port.find('state').get('reason_ttl')if port.find('state') is not None else "unkown",
                name = port.find('service').get('name')if port.find('service') is not None else "unkown",
                method = port.find('service').get('method')if port.find('service') is not None else "unkown",
                conf = port.find('service').get('conf')if port.find('service') is not None else "unkown"
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

        #self.__parser = Parser()

    #Need better return
    def run_scan_port(self) -> bool:
            in_handler = InputHandler()
            self.__usr_ip = in_handler.get_input_ip()
            self.__usr_filename = in_handler.get_input_file()
            scanner = Scanner(self.__usr_ip, self.__usr_filename)
            scanner.scan_xml()
            parser = Parser(self.__usr_filename)
            self.__report = parser.parse_xml_port()
            reporter = Reporter(self.__usr_filename, self.__report)
            reporter.write_xml_txt()
            return True
#####MAIN
def main():
    manager = Manager()
    manager.run_scan_port()

if __name__ == "__main__":
    main()

