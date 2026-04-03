#James McKinley
#NmapParser Poject
from dataclasses import dataclass
import subprocess 
import xml.etree.ElementTree as ET

#Helper Classes
@dataclass(frozen=True)     #Class decorator requied to use syntax
class ParserResult:
    protocol:str
    portid: int
    state:str
    reason:str
    reason_ttl:str
    name:str
    method:str
    conf:str

#Main Classes
class Scanner:
    def __init__(self, usr_ip: str,usr_filename: str):
        self.__scanner_ip = usr_ip
        self.__scanner_filename = usr_filename

    def scan_xml(self):
        subprocess.run(["nmap", "-sV", "-oX", f"{self.__scanner_filename}", f"{self.__scanner_ip}"])
        #Need process for invalid ip or filename response
            
class Parser:
    def __init__(self, usr_filename: str):
        self.__parser_filename = usr_filename
        self.__parser_list = []

    def parse_xml_port(self):      #Thinking of renaming to better fit the nmap argument description "-sV"
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

        
        
