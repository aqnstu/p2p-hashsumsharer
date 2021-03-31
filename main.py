import os           # для выхода из приложения


def main():
    import hashlib  # для работы c md5
    import numpy    # для строгих типов (например, uint16)
    import pickle   # для сериализации и десериализации
    import socket   # для работы с сокетами Беркли
    import time     # для задержки вывода
    import uuid     # для получения MAC


    MSG_REQUEST_CODE = '0'      # код запроса
    MSG_RESPONSE_CODE = '1'     # код ответа
    MSG_REQUEST_FILE_HOLDING_CODE = '5' # код запроса, владеем ли мы файлом
    MSG_RESPONSE_FILE_HOLDING_CODE = '7' # код ответа, что мы владеем файлом

    REQUEST_INTERVAL = 5        # интервал, через который осуществляется повторно запрос в секундах

    PORT_NUMBER = numpy.uint16(65112)   # номер порта

    info_about_me = []          # информация обо мне в формате: имя, город = адрес, телефон
    online_users = []           # список имен всех пользователей онлайн и соответствующих им id
    users_id_hashes = []        # список всех хэшей от id пользователей
    file_name_hashes = []       # массив хэшей от имен файлов
    file_info_hashes = []       # массив хэшей от содержания файлов
    file_name_md5_xor_user_id_md5 = []  # массив xor-ов от имени файла и id пользователя
    users_ip = []               # массив с IP-адресами пользователей; users_ip[0] -- наш адрес


    # получить ip-адрес для отправки сообщений всем узлам локально сети
    def getLocalBroadcastHostIP():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 1))
        local_ip_address = sock.getsockname()[0]
        l = local_ip_address.split('.')
        l[3] = '255'
        broadcast_host_ip = '.'.join(l)
        return broadcast_host_ip


    # получить ip-адрес хоста
    def getLocalHostIP():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 1))
        local_ip_address = sock.getsockname()[0]
        l = local_ip_address.split('.')
        host_ip = '.'.join(l)
        return host_ip


    # получить MAC-адрес интерфейса eth0
    def getHostMac():
        return ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])   # получаем MAC


    # названия файла с карточкой пользователя в папке 'docs'
    card_name = input("\nEnter filename with card (ex. <name>.txt): ")
    # считываем информацию о себе в следующей последовательности: имя, город = адрес, телефон
    with open('docs/' + card_name, 'r') as fo:
        info_about_me = fo.readlines()
    # оформляем подписи к столбцам для хранилища    
    with open('docs/file-storage.txt', 'w') as fo:
        fo.write("Name\tID\t\t\t\t\tFilename\t\t\t\t\t\t\tFilesize\n")

    # инициализируем широковешательный неблокируемый UDP-сокет и связываем его с локальным адресом
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    broadcast_socket.setblocking(False)
    broadcast_socket.bind(('', PORT_NUMBER))
    print(f"Starting up on {socket.gethostname()} via port number {PORT_NUMBER}")

    # заполняем значиимые поля
    username = info_about_me[0].rstrip()
    username_length = numpy.uint16(len(username))
    user_id = str(int(round(time.time() * 1000))).rjust(16, '0')

    # хэш для id пользователя
    user_id_md5 = hashlib.md5()
    user_id_md5.update(user_id.encode())
    user_id_md5 = hex(int(user_id_md5.hexdigest(), 16))
    print(f"User ID hash: {user_id_md5}")

    # хэш для файла по его имени
    file_name_md5 = hashlib.md5()
    file_name_md5.update(card_name.encode())
    file_name_md5 = hex(int(file_name_md5.hexdigest(), 16))
    print(f"Filename hash: {file_name_md5}")

    # хэш для файла по его содержанию
    info_about_me_str = ''.join(info_about_me)
    file_info_md5 = hashlib.md5()
    file_info_md5.update(info_about_me_str.encode())
    file_info_md5 = hex(int(file_info_md5.hexdigest(), 16))
    print(f"File information hash: {file_info_md5}")

    # выводи IP пользователя в консоль
    user_ip = getLocalHostIP()
    print(f"IP address (IPv4): {user_ip}")


    # xor для двух строк с шестнадцатеричными числами разной длины
    def getDistance(a, b):
        if len(a) > len(b):
            return '%d' % (int(a[:len(b)],16)^int(b,16))
        else:
            return '%d' % (int(a,16)^int(b[:len(a)],16))


    # находим индекс наименьшего элемента в списке
    def findMinElemIndexInList(L):
        return L.index(min(L))


    # отправляем запрос всем пользователям онлайн
    def sendRequestToOnlineUsers(broadcast_socket, user_id, username_length,
                                username):
        # заполняем поля для запроса
        msg_request = []
        msg_request.append(MSG_REQUEST_CODE)
        msg_request.append(user_id)
        msg_request.append(username_length)
        msg_request.append(username)
        pickle_msg_request = pickle.dumps(msg_request)
        broadcast_socket.sendto(pickle_msg_request, (getLocalBroadcastHostIP(), PORT_NUMBER))
        
        
    # запрос ближайшему соседу на отправку дополнительной информации о своей информационной карточке
    def sendRequestToGetInfoFromNearestUser(broadcast_socket, user_id, file_name_md5,
                                            file_info_md5, info_about_me, username_length, username,
                                            users_id_hashes, user_id_md5, users_ip):
        for i in range(len(users_id_hashes)):
            if users_id_hashes[i] != user_id_md5:
                # наш аналог метрики
                dist = getDistance(file_name_md5, users_id_hashes[i])
                if dist not in file_name_md5_xor_user_id_md5:
                    file_name_md5_xor_user_id_md5.append(dist)
        if users_id_hashes and file_name_md5_xor_user_id_md5:
            i_min = findMinElemIndexInList(file_name_md5_xor_user_id_md5)
            dest_IP = users_ip[i_min]
            # заполняем поля для запроса
            msg_request = []
            msg_request.append(MSG_REQUEST_FILE_HOLDING_CODE)
            msg_request.append(user_id)
            msg_request.append(file_name_md5)
            msg_request.append(file_info_md5)
            info_length = numpy.uint16(len(info_about_me))
            msg_request.append(info_length)
            msg_request.append(username_length)
            msg_request.append(username)
            pickle_msg_request = pickle.dumps(msg_request)
            broadcast_socket.sendto(pickle_msg_request, (dest_IP, PORT_NUMBER))
        
        
    # обраатываем все возможные сообщения, которые могут прийти от других узлов
    def processReceivedMessage(broadcast_socket, online_users, user_id,
                            username_length, username, info_about_me,
                            users_id_hashes):
        pickle_msg, address = broadcast_socket.recvfrom(512)
        if pickle_msg:
            msg = pickle.loads(pickle_msg)
            if msg[0] == MSG_REQUEST_CODE:
                msg_response = []
                msg_response.append(MSG_RESPONSE_CODE)
                msg_response.append(user_id)
                msg_response.append(username_length)
                msg_response.append(username)
                pickle_msg_response = pickle.dumps(msg_response)
                broadcast_socket.sendto(pickle_msg_response, (getLocalBroadcastHostIP(), PORT_NUMBER))
            elif msg[0] == MSG_RESPONSE_CODE:
                if (msg[3], msg[1]) not in online_users:
                    online_users.append((msg[3], msg[1]))
                    if address[0] != getLocalHostIP():
                        users_ip.append(address[0])
                    user_id_neighbour_md5 = hashlib.md5()
                    user_id_neighbour_md5.update(msg[1].encode())
                    user_id_neighbour_md5 = hex(int(user_id_neighbour_md5.hexdigest(), 16))
                    if user_id_neighbour_md5 not in users_id_hashes:
                        users_id_hashes.append(user_id_neighbour_md5)
            elif msg[0] == MSG_REQUEST_FILE_HOLDING_CODE:
                msg_response = []
                msg_response.append(MSG_RESPONSE_FILE_HOLDING_CODE)
                msg_response.append(user_id)
                msg_response.append(file_name_md5)
                info_length = numpy.uint16(len(info_about_me))
                msg_response.append(info_length)
                msg_response.append(username_length)
                msg_response.append(username)
                pickle_msg_response = pickle.dumps(msg_response)
                broadcast_socket.sendto(pickle_msg_response, (address[0], PORT_NUMBER))
            elif msg[0] == MSG_RESPONSE_FILE_HOLDING_CODE:
                if (msg[5], msg[1]) != (username, user_id) and msg[1] not in open('docs/file-storage.txt').read():
                    # вывод значимых (имхо) строк в хранилище
                    with open('docs/file-storage.txt', 'a') as fo:
                        fo.write("%s\t" % msg[5])
                        fo.write("%s\t" % msg[1])
                        fo.write("%s\t" % msg[2])
                        fo.write("%s\t" % msg[3])
                        fo.write('\n')
            
                    
    # цикл с обработкой сообщений пирам
    # попробовал отказаться от многопоточной обработки
    # вышло так себе
    # опыт получен, буду теперь продумывать функционал для исходя из многопоточности
    while True:
        # ждём чуда, что все необходимые для работы списки заполняться и файлохранилице тоже
        for i in range(100):
            sendRequestToOnlineUsers(broadcast_socket, user_id, username_length, 
                                    username)
            processReceivedMessage(broadcast_socket, online_users, user_id,
                                username_length, username, info_about_me,
                                users_id_hashes)
            sendRequestToGetInfoFromNearestUser(broadcast_socket, user_id, file_name_md5,
                                                file_info_md5, info_about_me, username_length, username,
                                                users_id_hashes, user_id_md5, users_ip)
            processReceivedMessage(broadcast_socket, online_users, user_id,
                                username_length, username, info_about_me,
                                users_id_hashes)
        # все списки заполнились, но файлозранилище возможно пустое, через несколь итераций всё будет в порядке
        if online_users:
            print("\nCurrent online:")
            while online_users:
                user_info = online_users.pop()
                print(f"{user_info[0]}-{user_info[1]}")
            print("Waiting for 5 seconds...") 
        time.sleep(REQUEST_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    # чтобы не думать особо про выход из программы
    # обрабатываем KeyboardInterrupt как успешный выход
    except KeyboardInterrupt:
        print("\n")
        print("You have closed the connection!")
        print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
        os._exit(0)