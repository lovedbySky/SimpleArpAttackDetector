import subprocess
from time import sleep

class Detector:
    def __init__(self, router_MAC: str, interval: int):
        self.truth_table = self.__get_arp_table()
        self.router_MAC = router_MAC
        self.interval = interval


    def __get_arp_table(self):
        arp_table = subprocess.check_output(['arp', '-a'], encoding='UTF-8').splitlines()
        return arp_table


    def run(self):
        current_table = self.__get_arp_table()
        if self.router_MAC not in current_table[-1]:
            print(f'\n[!] An ARP attack may have been launched (Router MAC was changed) [!]')
            print(f'\tcurrent table > {current_table}')
            print(f'\tbase table > {self.router_MAC}\n')
        elif current_table != self.truth_table:
            print(f'\n[!] An ARP attack may have been launched (ARP Table was changed) [!]\n')
        else:
            print(f'[-] Any ARP attack not detected.')

        sleep(self.interval)
        self.run()


if __name__ == '__main__':
    obj = Detector('11:22:33:44:55:66', 5) #as example
    try:
        obj.run()
    except KeyboardInterrupt:
        print('\n [-] Quiting..')    
