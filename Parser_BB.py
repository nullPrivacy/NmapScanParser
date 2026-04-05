#James McKinley
#NmapParser Project Black Box Test v0.1.0

import Parser
import pytest
from Parser import InputHandler, Scanner, Parser, Reporter

@pytest.fixture
def setup_scanner():
    object = Scanner("127.0.0.1", "BlackBoxTestFile")
    return object

## SCANNER CLASS TEST
#*********************

#Subprocess returns 0 for success/!=0 when failure
def test_scanner_input():
    test_ip_good =  "127.0.0.1"
    test_ip_bad = "NotGoodIP"
    success_condition = 0
    fail_condition = 1

    test_file_name = "GoodFileName"

    test_scanner = Scanner(test_ip_good, test_file_name)
    assert test_scanner.scan_xml() == success_condition

    ##test_scanner = Scanner(test_ip_bad, test_file_name)
    ##assert test_scanner.scan_xml() == fail_condition
    
    test_scanner = Scanner(test_ip_bad, test_file_name)
    with pytest.raises(ValueError, match = "No Hosts Available"):
        test_scanner.scan_xml()
   
