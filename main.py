import datetime
import hashlib

data1 = {
    1: '5084972163',
    2: '9801567243',
    3: '7286059143',
    4: '1850394726',
    5: '1462578093',
    6: '5042936178',
    7: '0145937682',
    8: '0964238571',
    9: '3497651802',
    10: '9125780643',
    11: '8634972150',
    12: '5924673801',
    13: '8274053169',
    14: '5841792063',
    15: '2469385701',
    16: '8205349671',
    17: '7429516038',
    18: '3769458021',
    19: '5862370914',
    20: '8529364170',
    21: '7936082154',
    22: '5786241930',
    23: '0728643951',
    24: '9418360257',
    25: '5093287146',
    26: '5647830192',
    27: '3986145207',
    28: '0942587136',
    29: '4357069128',
    30: '0956723814',
    31: '1502796384'
}

class Password:
    def get_passwd(passwd, day=datetime.date.today().day, salt=1):
        passwdbyte = [ord(n) for n in passwd]
        ps_len = len(passwd)
        passwd_token = list(range(0, ps_len))
        date_token = Password.get_date_token(day, salt)
        index1 = 0 
        index2 = 0
        for i in range(0, ps_len):
            index1 += 1 & 255
            index1 %= 256
            index2 += date_token[index1] & 255
            index2 %= 256
            temp = date_token[index1]
            date_token[index1] = date_token[index2]
            date_token[index2] = temp
            index = date_token[index1] + date_token[index2] & 255
            index %= 256
            passwd_token[i] = 256 + date_token[index] ^ passwdbyte[i]
            passwd_token[i] %= 256

        m2 = hashlib.md5()
        m2.update(bytes(passwd_token))
        return m2.hexdigest()[8:24]

    def get_date_token(day, salt):
        word = data1.get(day)    
        word_len = len(word)
        wordbyte = [int(w) for w in word]
        token = [n if n < 128 else n-256 for n in range(0, 256)]
        index = 0
        for i in range(0, 256):
            index += token[i] + ((wordbyte[i % word_len]) & (255))
            index %= 256
            temp = token[i]
            token[i] = token[index]
            token[index] = temp
        return token

def show_passwd(passwd):
    for i in range(1,32):
        print(i,"=",Password.get_passwd(passwd, i, 1), sep='')

def package_passwd(passwd):
    pck = {}
    for i in range(1, 32):
        pck[str(i)] = Password.get_passwd(passwd, i, 1)
    return pck  # 返回存储密码哈希值的字典


############################
        
import sys, requests, configparser, time, json, os
import traceback
from xml.etree import ElementTree
from urllib import parse



def load_config(phone: str, pwd: str) -> None:
    today = time.strftime('%d', time.localtime(time.time()))
    login_pwd = Password.get_passwd(pwd, int(today), 1) # 获取当天的密码哈希值
    if login_pwd == "":
        input(str(today) + "号的登陆密码尚未配置")
        return
    # 执行登录操作
    do_login(phone, login_pwd)


def do_login(phone: str, pwd: str) -> None:
    '''
    认证主方法
    :param phone: 手机号
    :param pwd:   密码
    :return:
    '''
    url = 'http://www.baidu.com/'
    print('-----------------------------------')
    try:
        redirect_url = requests.get(url, timeout=10).url
    except:
        input('请插拔路由器的电源')
        return
    if len(url) == len(redirect_url):
        input('当前设备已经链接互联网')
        return

    redirect_url_parse = parse.parse_qs(parse.urlparse(redirect_url).query)

    # 获取此次重定向的100.64的内网地址
    user_ip = redirect_url_parse['userip']

    # 获取需要登陆的设备MAC地址
    user_mac = redirect_url_parse['usermac']

    # 获取认证服务器的IP地址
    nas_ip = redirect_url_parse['nasip']

    # post请求飞扬地址 获取响应的xml最终登陆内容
    header = {
        'User-Agent': 'CDMA+WLAN(Maod)',
        'Host': '58.53.199.144:8001',
        'Connection': 'Keep - Alive',
        'Accept - Encoding': 'gzip'
    }
    url = 'http://58.53.199.144:8001'
    data = {
        'userip': user_ip,
        'wlanacname': '',
        'nasip': nas_ip,
        'usermac': user_mac,
        'aidcauthtype': '0'
    }
    response_login_info_xml = requests.post(url, headers=header, data=data)
    # 获得最终URL地址,登录POST URL
    StrResponse = response_login_info_xml.text

    ResponseData = ElementTree.XML(StrResponse.encode('utf-8').decode('utf-8'))
    # 获得认证的URL
    url2 = ResponseData.find('Redirect').find('LoginURL').text
    data1 = {
        "UserName": "!^Adcm0" + phone,
        "Password": pwd,
        "AidcAuthAttr1": ResponseData.find('Redirect').find('AidcAuthAttr1').text,  # 获取当前时间
        "AidcAuthAttr3": "KQSNcAp2",
        "AidcAuthAttr4": "V0TYDlQ73yQEPWkxCGym4Ls=",
        "AidcAuthAttr5": "KRiKcAhgnDF+RGoxCHKr5aQS46ZrjX3VVRrp1+4oKIWqNs3sVMBk3lz2zk+txME=",
        "AidcAuthAttr6": "KW+HbX107y91Rm47C2yn4bs=",
        "AidcAuthAttr7": "",
        "AidcAuthAttr8": "",
        "AidcAuthAttr15": "KR2ObQw=",
        "AidcAuthAttr22": "KA==",
        "AidcAuthAttr23": "a1/ePV093w==",
        "createAuthorFlag": "0"
    }
    login_info = requests.post(url2, data=data1, headers=header).text

    ResponseData2 = ElementTree.XML(login_info.encode('utf-8').decode('utf-8'))
    # 打印认证信息
    print('--------------登陆状态---------------------')
    print(ResponseData2.find('AuthenticationReply').find('ReplyMessage').text)
    input('------------------------------------------')



if __name__ == '__main__':
    phone = input("INPUT YOUR PHONE:")
    pin = input("INPUT YOUR PASSWORD:")
    show_passwd(pin)
    try:
        #登陆
        load_config(phone,pin)        
    except Exception as e:
        traceback.print_exc()
        input("出现如下异常:%s" % e)    