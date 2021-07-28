
import socket
import sys
import os
import random
from sympy import randprime,mod_inverse,isprime
import asn1
import sympy
import math

from sys import getdefaultencoding
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


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
    return integers[0]

def to_asn(p,r,t_a):
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
    encoder.write(p, asn1.Numbers.Integer)
    encoder.write(r, asn1.Numbers.Integer)
    encoder.leave()  # Вышли из последовательности открытого ключа
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence)  # Параметры криптосистемы, в RSA не используются
    encoder.write(t_a, asn1.Numbers.Integer)
    encoder.leave()
    encoder.leave()
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()


    return encoder.output()
def to_asn_aes(t_b,ciphertext,len):
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
    encoder.leave()  # Вышли из последовательности открытого ключа
    encoder.enter(asn1.Numbers.Sequence)  # Параметры криптосистемы, в RSA не используются
    encoder.write(t_b, asn1.Numbers.Integer)
    encoder.leave()
    encoder.leave()
    encoder.leave()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(b'\x10\x82', asn1.Numbers.OctetString)  # идентификатор алгоритма шифрования AES CBC
    encoder.write(len, asn1.Numbers.Integer)  # Длина шифровтекста

    encoder.leave()
    encoder.leave()
    encoder.write(ciphertext)

    return encoder.output()

def client(ip_addr,port,filename):
    sock = socket.socket()
    sock.settimeout(10)
    sock.connect((ip_addr, port))
    print('\nConnected to server %s:%s' % (ip_addr, port))
    print('step 1')


    r = randprime(2 ** 1024,2 ** 1027)


    p = randprime(2 ** 1024, 2 ** 1027)

   # j = (r - 1) // q
    j = 2
    while 1:
        h = random.randint(2, r - 2)
        a = pow(h, j, r)
        if a != 1:
            try:
                a_1 = mod_inverse(a, r - 1)
                break
            except ValueError:
                print("no ok")

    print("check=" + str((a * a_1) % (r - 1)))
    mes = 123456789123456789
    t = (mes*213) % r
    print("t="+str(t))

    print("p="+str(p))
    print("r="+str(r))
    t_a = pow(t, a, r)
    print("t_a="+str(t_a))
    #t_a_a_1=pow(t_a,a_1,r)
   # print("t_a_a_1="+str(t_a_a_1))
    encoded=to_asn(p,r,t_a)
    sock.send(encoded)
    print('step 2 ')
    asn1_blob = sock.recv(1024)
    assert_rcv(asn1_blob)

    t_ab=from_asn(asn1_blob)
    print("t_ab="+str(t_ab))
    t_ab_a_1=pow(t_ab,a_1,r)
    print("t_b="+str(t_ab_a_1))
    k=mes % 2**256
    data='abcd'
    print("data="+str(data))
    leng=len(data)
    while len(data)!=16:
        data=data+'3'
   # print(data)
    iv = b'\x00' * AES.block_size
    k=k.to_bytes(AES.key_size[-1], "big")
    getdefaultencoding()
    type(data)
    new_data=data.encode()

   # print(AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC,iv)
   # print(AES.block_size)
    ciphertext = cipher.encrypt(pad(new_data, AES.block_size))
   # print(len(ciphertext))
    print("encrypted_data="+str(ciphertext))
    new_enc=to_asn_aes(t_ab_a_1,ciphertext,leng)
    sock.send(new_enc)




if __name__ == '__main__':

    ip_addr='127.0.0.1'
    port=9000
    filename='enc.txt'
    client(ip_addr,port,filename)
