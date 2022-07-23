import subprocess
import requests
from utils.settings import MAIN_PATH


class Tools:
    # noinspection PyMethodMayBeStatic
    def terminal_command(self, command: str, is_print_error=True):
        ret = None
        try:
            ret = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL)
        except Exception as e:
            if is_print_error:
                print(f"Command {command} returned error exit code {e}")

        if type(ret) is bytes:
            try:
                ret = ret.decode('ascii')
            except:
                if is_print_error:
                    print("Wasn't able to convert binary to string")
        return ret

    def get_md5(self):
        files_dict = {}
        output_str = self.terminal_command(f"ls {MAIN_PATH}")
        files_arr = output_str.split('\n')
        for file in files_arr:
            md5 = self.terminal_command(command=f"md5sum {MAIN_PATH}/{file}", is_print_error=False)
            if md5 is not None:
                files_dict[file] = md5
        return files_dict

    # noinspection PyMethodMayBeStatic
    def get_malware_feed(self):
        all_md5 = []
        malware_feed_url = "https://virusshare.com"
        ret = requests.get(f"{malware_feed_url}/hashes")
        try:
            feed_len = len(ret.text.split("MD5 List Downloads:")[1].split("<p>")[0].split("</a>,")) - 1
        except:
            feed_len = 429  # The total number of pages at 23/7/2022

        # Checking only in the first 2 pages of the feed because the feed is huge, so it will take a lot of time-
        # If I had subscription I could search directly for the md5, but I don't have. This code is generic so once
        # I will have subscription I can just delete the following line.
        feed_len = 1

        for i in range(0, feed_len):
            page_num = f"{i}"
            padding = "0" * (5 - len(page_num))
            page_num = f"{padding}{page_num}"
            url = f"{malware_feed_url}/hashfiles/VirusShare_{page_num}.md5"
            ret = requests.get(url)
            all_md5 = all_md5 + ret.text.split('\n')
        return all_md5
