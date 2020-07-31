import base64
import hashlib
import hmac
import json
import time
import re

import bs4
import requests
from Crypto.Cipher import AES
import vk_api
from vk_api.utils import get_random_id
from vk_api.bot_longpoll import VkBotLongPoll, VkBotEventType
import urllib3
from keys import *
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HMAC_SECRET_KEY = HMAC

cipher_key = cipher_k
gc_token = gc_token

DBG = "DBG: "  # Не забудь удалить
max_tags = 16


class AESCipher(object):
    def __init__(self, key):
        self.bs = 32
        self.key = base64.b64decode(key)

    def encrypt(self, raw):
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(raw.encode('utf-8'))).decode()

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return self._unpad(cipher.decrypt(enc)).decode('utf-8', errors='ignore')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


class GetContact(object):

    def __init__(self):
        pass

    def gc_get_inf(phone, mode):
        if mode == 'search':
            source = 'search'
            meth = 'search'
        elif mode == 'detail':
            source = 'detail'
            meth = 'number-detail'
        else:
            raise Exception('unknown mode')

        cipher = AESCipher(cipher_key)

        payload = {
            "phoneNumber": phone,
            "source": source,
            "token": gc_token
        }

        timestamp = str(round(time.time() * 1000))

        burp0_headers = {
            "X-App-Version": "4.2.0",
            "X-Req-Timestamp": timestamp,
            "X-Os": "android 6.0.1",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 6.0.1; Redmi 4 MIUI/8.1.11)",
            "X-Token": gc_token,
            "X-Encrypted": "1",
            "X-Client-Device-Id": "8ad62b3d23795f5f",
            "X-Lang": "ru_RU",
            "Content-Type": "application/json; charset=utf-8",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate"
        }

        serialized_payload = json.dumps(payload)
        serialized_payload = serialized_payload.replace(' ', '')

        encrypted_data = cipher.encrypt(serialized_payload)

        signature_str = '{}-{}'.format(timestamp, serialized_payload)
        dig = hmac.new(HMAC_SECRET_KEY, msg=signature_str.encode(), digestmod=hashlib.sha256).digest()
        signature = base64.b64encode(dig).decode()
        burp0_headers['X-Req-Signature'] = signature

        dtt = json.dumps({"data": encrypted_data})
        req = requests.post('https://pbssrv-centralevents.com:443/v2.1/' + meth, headers=burp0_headers, data=dtt,
                            verify=False)
        resp_encrypted = req.json()
        resp_encrypted = resp_encrypted['data']
        resp = cipher.decrypt(resp_encrypted)
        resp_json = json.loads(resp)

        return resp_json

    def parse_tags(self):
        search = GetContact.gc_get_inf(self, 'search')
        resp_arr = []
        try:
            profile = search['result']['profile']
            disp_name = profile['displayName']
            tag_count = profile['tagCount']
        except KeyError:
            return resp_arr

        if disp_name is not None:
            resp_arr.append(disp_name)

        if tag_count == 0:
            return resp_arr

        details = GetContact.gc_get_inf(self, 'detail')

        try:
            tags = details['result']['tags']
        except KeyError:
            return resp_arr

        for tag in tags:
            resp_arr.append(tag['tag'])
        resp_arr.insert(0, tag_count + 1)
        return resp_arr


class Avito(object):

    def __init__(self):
        pass

    @staticmethod
    def vk_avito_parse(number):
        try:
            avito_answer = ""
            res = requests.get("https://mirror.bullshit.agency/search_by_phone/" + str(number))
            b = bs4.BeautifulSoup(res.text, "html.parser")
            title = b.find('title')
            print(title.string)
            if "Нет объявлений по телефону" or "Bad gateway" in title.string:
                return "Объявления Авито не найдены или ошибка работы сервиса"
            a = b.find_all(href=True, rel="nofollow")[0]['href']
            resn = requests.get("https://mirror.bullshit.agency" + str(a))
            n = bs4.BeautifulSoup(resn.text, "html.parser")
            name = n.select('strong')[0].getText()
            t = b.select('h4')
            p = b.select('p')
            for i in range(len(t)):
                avito_number = str(i + 1) + "\n"
                avito_name = t[i].getText()
                avito_address = p[i].select('span')[0].getText()
                avito_date = p[i].select('span')[1].getText()
                avito_answer = avito_answer + "\n" + "Объявление " + avito_number + "\nНазвание : " + avito_name + "\nАдрес : " + avito_address + "\nДата : " + avito_date
            return avito_answer
        except:
            return "Ошибка поиска Авито"

class Handler(object):  # Внутрь передается команда пользователя
    number = 0  # номер телефона
    command = ""  # команда

    # date = "" #  дата todo расписание

    def __init__(self, command):
        self.number = re.search(r'(\+7|8|7|9).*?(\d{2,3}).*?(\d{3}).*?(\d{2}).*?(\d{2})', command)
        if self.number:
            self.number = self.number[0]
        self.command = re.search(r'(\D{,32})', command)
        if self.command:
            self.command = self.command[0]
        pass

    def get_number(self):
        return self.number[0]

    def get_command(self):
        return self.command[0]

    @staticmethod
    def get_gc_tags(number):
        # noinspection PyCallByClass
        full_answer_gc = GetContact.parse_tags(number)
        full_answer = [0, ""]

        full_answer[0] = full_answer_gc[0]  # Сколько всего тегов

        full_answer_gc.pop(0)
        full_answer_gc = full_answer_gc[:max_tags]  # Максимум 16 тегов
        tags = ', '.join(map(str, full_answer_gc))

        full_answer[1] = tags
        return full_answer  # Элемент с индексом 0 - колличество тегов

    @staticmethod
    def get_avito_ads(number):
        ads = Avito.vk_avito_parse(number)
        return ads

    @staticmethod
    def error():
        return "Вы ввели некоректную команду\n\nДля того чтобы найти всю информацию о номере - просто отправьте номер," \
               " пример сообщения \'88005553535\'\n\nДля того чтобы найти номер в базе GetContact - введите команду \'\\gc" \
               " номер\', пример сообщения \'\\gc 88005553535\'\n\nДля того чтобы найти номер среди объявлений Авито -" \
               " введите команду \'\\av номер\', пример сообщения \'\\av 88005553535\'"

    def result(self):

        if (self.command == '/gc ' or self.command == 'проверка') and self.number:
            full_answer = self.get_gc_tags(self.number)
            answer = "Всего тегов: " + str(full_answer[0]) + "\n"
            if max_tags < full_answer[0]:
                answer += "Первые " + str(max_tags) + " из них: "
            answer += full_answer[1]
            return answer

        if (self.command == 'авито ' or self.command == '/av') and self.number:
            return self.get_avito_ads(self.number)

        if self.command == "" and self.number:
            answer = "Теги к номеру: " + self.get_gc_tags(self.number)[
                1] + "\n\n" + "Объявления авито:\n" + self.get_avito_ads(self.number)
            return answer

        else:
            return self.error()

    @staticmethod
    def privacy():
        answer = "Начиная пользоваться данным ботом вы подтверждаете согласие на обработку, хранение и использование персональных данных"
        return answer


class VK(object):
    group_id = group
    vk_session = vk_api.VkApi(
        token=vk_token)
    longpoll = VkBotLongPoll(vk_session, group_id)
    vk = vk_session.get_api()

    def __init__(self):

        pass

    def send_message(self, event, msg_text):
        self.vk.messages.send(
            user_id=event.obj['from_id'],
            random_id=get_random_id(),
            message=msg_text,
        )
        pass

    def parser(self):
        for event in self.longpoll.listen():
            if event.type == VkBotEventType.MESSAGE_NEW and event.obj['text'] != '':
                #print(event.obj)
                #print(event)
                self.send_message(event, Handler(event.obj['text']).result())


if __name__ == "__main__":
    try:
        user = VK()
        user.parser()
    except:
        pass
# Организовал получение сообщений от вк
# todo обработку сообщений, разобраться с апи фотографий и кнопок
