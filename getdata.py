from searchvti import searchVTI
import sys
import json
from pprint import pprint

vti_handle = searchVTI()
vti_handle.load_config('config.json')
results = vti_handle.parse_file(sys.argv[1])
#results = vti_handle.parse_cli(sys.argv[1])
#pprint(results)
vti_results = vti_handle.get_vti_data(results)
#json.dumps(vti_results)
pprint(vti_results)
