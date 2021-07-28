
import socket
import sys
import os
import asn1
import sympy
import math

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import random
from sys import getdefaultencoding
from sympy import randprime,mod_inverse
def assert_rcv(data):
    if not data:
        raise Exception('data is None')
def parse(decoder, integers): # такой же парсер, как и в шифровании
    while not decoder.eof():
        try:
            tag = decoder.peek()

            if tag.nr == asn1.Numbers.Null:
                break

            if tag.typ == asn1.Types.Primitive:
                tag, value = decoder.read()

                if tag.nr == asn1.Numbers.Integer:
                    integers.append(value)

            else:
                decoder.enter()
                integers = parse(decoder, integers)
                decoder.leave()

        except asn1.Error:
            break

    return integers

def from_asn(asn1task):
    integers = []
    decoder = asn1.Decoder()
    decoder.start(asn1task)
    integers = parse(decoder, integers)
    cipher = asn1task[-integers[-1]:]
    return integers[0], integers[1], integers[2]
def from_asn_aes(asn1task):
    integers = []
    decoder = asn1.Decoder()
    decoder.start(asn1task)
    integers = parse(decoder, integers)
   # cipher = asn1task[-integers[-1]:]
    lengt=integers[1]
    cipher_bytes = bytearray()
    while lengt%16!=0:
        lengt+=1
    cip=0
    lengt+=16
   # print("okkk")
   # print(len[asn1task])
    cip=asn1task[len(asn1task)-lengt:len(asn1task)]
   # print(cip)
    return integers[0], integers[1], cip
def to_asn(t_ab):
    my_string = 'mo'
    getdefaultencoding()
    type(my_string)
    mo=my_string.encode()
    encoder = asn1.Encoder()
    encoder.start()

    encoder.enter(asn1.Numbers.Sequence)  # Основная последовательность
    encoder.enter(asn1.Numbers.Set)  # Набор ключей RSA
    encoder.enter(asn1.Numbers.Sequence)  # Последовательность -- первый ключ RSA

    encoder.write(b'\x80\x07\x02\x00', asn1.Numbers.OctetString)  # идентификатор RSA
    encoder.write(mo, asn1.Numbers.UTF8String)  # Необзяталеьный идентификатор ключа

    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(t_ab, asn1.Numbers.Integer)
    encoder.leave()
    encoder.leave()
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()
    encoder.leave()


    return encoder.output()
def server(ip_addr,port):
    sock = socket.socket()
    sock.bind((ip_addr, port))
    sock.listen(1)
    print('Server is running on %s:%s' % (ip_addr, str(port)))
    while True:
        conn, addr = sock.accept()
        print('\nConnected: ', addr)
        try:
            print("step 1")
            asn1_data= conn.recv(1024)
            assert_rcv(asn1_data)
            p,r,t_a=from_asn(asn1_data)

            ##print(i1)
            #print(i2)
           # print(i3)
            j = 2
            print("t_a="+str(t_a))
            while 1:
                h = random.randint(2, r - 2)
                b = pow(h, j, r)
                if b != 1:
                    try:
                        b_1 = mod_inverse(b, r - 1)
                        break
                    except ValueError:
                        print("no ok")

            print("check=" + str((b * b_1) % (r - 1)))
            t_ab =pow(t_a, b, r)
            print("t_ab="+str(t_ab))
            send=to_asn(t_ab)
            conn.send(send)
            asn1_new_data= conn.recv(4024)
            assert_rcv(asn1_new_data)
            t_b,len,cipher=from_asn_aes(asn1_new_data)
            print("b_1="+str(b_1))
            print("t_b="+str(t_b))
            t=pow(t_b,b_1,r)
            print("step 2")
            print("t="+str(t))
            m=(t//213) % r
            #m=int(m)
            print("m=" +str(m))
            k=m % 2**256
            k=k.to_bytes(AES.key_size[-1], "big")
            iv = b'\x00' * AES.block_size
            print("cipher="+str(cipher))

            decipher = AES.new(k, AES.MODE_CBC, iv)
            decrypted = unpad(decipher.decrypt(cipher), AES.block_size)
            decrypted=decrypted[0:len]
            print("decrypted_data="+str(decrypted))

          #  m1=mod_inverse(m,r)
           # print(m1)
        except Exception as e:
            print('Error occured: %s. Closing connection\n' % str(e))

        finally:
            conn.close()




if __name__ == '__main__':
    ip_addr='127.0.0.1'
    port=9000
    server(ip_addr,port)
