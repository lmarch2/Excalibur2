import requests.exceptions

def _update():
    welcome = '''
    # /$$$$$$$$                               /$$ /$$ /$$                          
    # | $$_____/                              | $$|__/| $$                          
    # | $$       /$$   /$$  /$$$$$$$  /$$$$$$ | $$ /$$| $$$$$$$  /$$   /$$  /$$$$$$ 
    # | $$$$$   |  $$ /$$/ /$$_____/ |____  $$| $$| $$| $$__  $$| $$  | $$ /$$__  $$
    # | $$__/    \  $$$$/ | $$        /$$$$$$$| $$| $$| $$  \ $$| $$  | $$| $$  \__/
    #  $$        >$$  $$ | $$       /$$__  $$| $$| $$| $$  | $$| $$  | $$| $$      
    # | $$$$$$$$ /$$/\  $$|  $$$$$$$|  $$$$$$$| $$| $$| $$$$$$$/|  $$$$$$/| $$      
    # |________/|__/  \__/ \_______/ \_______/|__/|__/|_______/  \______/ |__/      

    Welcome to Excalibur !
    '''
    print(welcome)
    print('checking for updates...')

    import subprocess
    import sys
    import requests
    from bs4 import BeautifulSoup

    try:
        # 获取最新版本信息
        # 发送 GET 请求，并设置超时时间为 10 秒
        url = "https://pypi.org/project/Excalibur2/#history"
        response = requests.get(url, timeout=10)

        # 检查响应状态码
        if response.status_code == 200:
            # 使用 BeautifulSoup 解析 HTML
            soup = BeautifulSoup(response.text, "html.parser")

            # 查找所有包含版本信息和日期的<a>标签
            version_tags = soup.find_all("a", class_="card release__card")
            if version_tags:
                flag = 0
                for version_tag in version_tags:
                    version_info = version_tag.find("p", class_="release__version").text.strip()
                    version_date = version_tag.find("time").text.strip()
                    if flag == 0:
                        latest_version = version_info
                    flag += 1
            else:
                print("未找到版本信息")
        else:
            print("请求失败:", response.status_code)

        try:
            # 运行 pip show 命令来获取已安装库的版本信息
            result = subprocess.run(["pip", "show", "Excalibur2"], capture_output=True, text=True)
            installed_version = None
            for line in result.stdout.split("\n"):
                if line.startswith("Version:"):
                    installed_version = line.split(":")[1].strip()
                    break

            # 检查版本是否一致，如果不一致则提示更新
            if installed_version != latest_version:
                print('\033[93m'+f"WARNING: Your version of Excalibur2 ({installed_version}) is outdated. Please update to version {latest_version}."+'\033[0m')
            else:
                print('\033[92m'+'The Version is latest'+'\033[0m')
        except Exception as e:
            print('\033[91m'+f"Error checking for updates: {e}"+'\033[0m')
    except requests.exceptions.Timeout or requests.exceptions.ConnectionError:
        print('\033[93m'+"WARNING: Network connection timed out. Please check your internet connection."+'\033[0m')


if __name__ == "__main__":
    _update()
