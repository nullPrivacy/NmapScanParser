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
    portid: int
    state:str
    reason:str
    reason_ttl:str
    name:str
    method:str
    conf:str

######Main Classes
class Scanner:
    def __init__(self, usr_ip: str,usr_filename: str):
        self.__scanner_ip = usr_ip
        self.__scanner_filename = usr_filename

    #Need process for invalid ip or filename response
    def scan_xml(self):
        subprocess.run(["nmap", "-sV", "-oX", f"{self.__scanner_filename}", f"{self.__scanner_ip}"])
            
class Parser:
    def __init__(self, usr_filename: str):
        self.__parser_filename = usr_filename
        self.__parser_list = []

    #Thinking of renaming to better fit the nmap argument description "-sV"
    def parse_xml_port(self):      
        tree = ET.parse(f"{self.__parser_filename}.xml")
        root = tree.getroot()

        for port in root.iter('port'):
            result = ParserResult( 
                protocol = port.get('protocol')if port.find('protocol') is not None else "unkown",
                port_id = port.get('portid')if port.find('portid') is not None else "unkown",
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
        self.__reporter_list = report_to_write
    #Add return value 
    def write_xml_txt(self):
        with open(f"{self.__reporter_filename}.txt", "w") as file:
            file.write(f"Protocol: {self.__reporter_list.protocol}\n")
            file.write(f"Port ID: {self.__reporter_list.port_id}\n")
            file.write(f"State: {self.__reporter_list.state}\n")
            file.write(f"Reason: {self.__reporter_list.reason}\n")
            file.write(f"Reason_ttl: {self.__reporter_list.reason_ttl}\n")
            file.write(f"Name: {self.__reporter_list.name}\n")
            file.write(f"Method: {self.__reporter_list.method}\n")
            file.write(f"Service: {self.__reporter_list.service}\n")
            file.write(f"---\n")

class Manager:
    def __init__(self):
        self.__scanner = Scanner()
        self.__parser = Parser()
        self.__reporter = Reporter()
        self.__usr_ip
        self._usr_filename
        self.__report = []

    def input_ip(self) -> bool:
        return True;   
