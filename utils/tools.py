import subprocess

from utils.settings import MAIN_PATH


class Tools:
    # noinspection PyMethodMayBeStatic
    def terminal_command(self, command: str):
        ret = None
        try:
            ret = subprocess.check_output(command, shell=True)
        except Exception as e:
            print(f"Command {command} returned error exit code {e}")

        return ret

    def get_md5(self):
        files_dict = {}
        output_binary = self.terminal_command(f"ls {MAIN_PATH}")
        output_str = output_binary.decode('ascii')
        files_arr = output_str.split('\n')
        for file in files_arr:
            md5 = self.terminal_command(f"md5sum {MAIN_PATH}/{file}")
            if md5 is not None:
                files_dict[file] = md5
        return files_dict
