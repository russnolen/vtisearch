# Setup
pip3 install -r requirements.txt

## Config.json
The config.json file holds the patterns/regexs that will be applied to the a string looking for various IOC types. 
Regexs for the following have been included:

* IP Addresses
* Domain Names
* MD5

The configuration file is also utilized to extended the searchVTI for IOCs patterns you can define yourself. See the Extending section below for details on how to do this

Also included in the config.json is a section for you VirusTotal API key (either public or private)


# Usage

searchVTI is a python module that when supplied a string will

1. Search the string for various IOCS (based on regex's defined in the config.json) file
2. Conduct some basic validation on the found items from the regex results (trying to limit false positives)
3. Query VirusTotal for the IOCs found in the string 

## Code Example

# Extending
You can extended searchVTI to include your own IOC types in just a few steps

Step 1: Add your regex to the ```ioc_types``` section of the config.json file 
Below is an example of adding a regex to search for urls

```	
"ioc_types": {
		"ipaddr":"(?:[0-9]{1,3}\\.){3}[0-9]{1,3}",
		"domain": "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]",
		"md5":"([a-fA-F\\d]{32})",
		"url": "https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
		},
```

Step 2:
In the ```get_vti_data``` function add the if statement for your ioc type (this must be the same string used as the key in the config.json)
```
   def get_vti_data(self, ioc_dict):
        vti_data = {}
        for ioc_type,iocs in ioc_dict.items():
            if ioc_type == 'domain':
                vti_data['domains'] =  self._handle_domain(iocs)
            if ioc_type == 'ipaddr':
                vti_data['ips'] = self._handle_ipaddr(iocs)
            if ioc_type == 'md5':
                vti_data['md5s'] = self._handle_md5(iocs)
            if ioc_type == 'url':
                vti_data['urls'] = self._handle_urls(iocs)

```

Step 3:
Once you have your if statement defined you need to create the handle function is where you will put your code. This is where 
you can do some pre-processing on the iocs being passed to the function. This allows you a little bit more freedom in your regex
so you can do tighter verification on the regex matches so you are not waisting VirusTotal api calls. 

The ```iocs``` passed to the handle function is a array of matches from your regex. So you will need to architect your handle function to
work on a array of objects. 


# Todo

1. Make a complete python package 
2. Port configuration file to yaml 
