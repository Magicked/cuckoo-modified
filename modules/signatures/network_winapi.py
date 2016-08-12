from lib.cuckoo.common.abstracts import Signature

class NetworkWinAPI(Signature):
    name = "network_winapi"
    description = "WinAPI calls to network hosts"
    severity = 2
    categories = ["network"]
    authors = ["magicked"]
    minimum = "0.5"

    def run(self):
        verdict = False

        keyargs = { 
                    'InternetConnectW' : 'ServerName',
                    'URLDownloadToFileW' : 'URL',
                    'InternetCrackUrlW' : 'Url',
                  }
        
        for proc in self.results['behavior']['processes']:
            for call in proc['calls']:
                if call['category'] == 'network':
                    if call['api'] in keyargs:
                        for arg in call['arguments']:
                            if arg['name'] == keyargs[call['api']]:
                                self.data.append( { call['api'] : arg['value'] } )
                                verdict = True

        return verdict
