#!/usr/bin/python3.5

import sys, argparse, textwrap

def function(i, k, r, length):
    #print("xoring: ", ((2*i*r)**k) % (10**(length+1)))
    return ((2*i*r)**k) % (10**(length))

def create_iv(var):
    length = len(str(abs(var)))
    iv = 1

    for i in range(0, length-1):
        iv = iv * 10

    print("iv",iv)
    return iv

def main(argv):
    l0 = 0
    r0 = 0
    l_old = 0
    r_old = 0
    l_cipher = 0
    r_cipher = 0
    l_new = 0
    r_new = 0
    k = 7
    iterations = 2

    plaintext = ''
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', action="store",dest="filename")
    parser.add_argument('-m', action="store",dest="message")

    if parser.parse_args().filename:
        filename = str(parser.parse_args().filename)
        file = open(filename)
        plaintext = file.read()
    elif parser.parse_args().message:
        file = open('input.txt', 'w+')
        file.write(parser.parse_args().message)
        file = open('input.txt', 'r')
        plaintext = file.read()

    if len(plaintext) % 2 != 0:
        plaintext.ljust(len(plaintext)+1,' ')

    num_of_blocks = 2
    length = int(len(plaintext)/num_of_blocks)
    start = 0
    end = length
    curr_block = ' '

    #split into blocks for CBC/CTR
    blocks = textwrap.wrap(plaintext, 2)
    print(blocks)

    for i in range(0, len(blocks)):
        #split block
        curr_block = blocks[i]
        l = blocks[i][:1]
        print(l)
        r = blocks[i][1:]
        print(r)

        if l == '':
            l_int = ord(' ')
        else:
            l_int = ord(l)
        print(l_int)

        if r == '':
            r_int = ord(' ')
        else:
            r_int = ord(r)
        print(r_int)

        #xor with IV
        if(i == 0):
            l_int_xor = create_iv(l_int) ^ l_int
            r_int_xor = create_iv(r_int) ^ r_int
        else:       #xor with last ciphertext
            l_int_xor = l_cipher ^ l_int
            r_int_xor = r_cipher & r_int

        print(l_int_xor)
        print(r_int_xor)

        #open file to write ciphertext
        cipher_file = open("results.txt", "w+")

        #print("number of digits:", len(str(abs(l0))))
        xor_length = len(str(abs(l_int_xor)))
        print("xor_length:",xor_length)

        l_old = l_int_xor
        r_old = r_int_xor

        #encrypt
        for i in range(1, iterations):
            l_new = r_old
            print("xoring: ", function(i, k, r_old, xor_length), "^", l_old)
            r_new = function(i, k, r_old, xor_length) ^ l_old

            #update nanmes for next iteration
            l_old = l_new
            r_old = r_new

            print("ciphertext")
            print("l new:", l_new)
            print("r new:", r_new)
            print()

        if(i != (len(blocks)-1)):
            l_cipher = l_new
            r_cipher = r_new
        cipher_file.write(str(l_new))
        cipher_file.write(str(r_new))
        cipher_file.close()


    #open file to write ciphertext
    decrypted_file = open("decrypted_results.txt", "w+")

    #decrypt
    for i in range(len(blocks)-1, 0, -1):
        for i in range(iterations-1,0 -1):
            xor_length = len(str(abs(l_new)))

            r_new = l_old
            print("xoring: ", function(i, k, r_new, xor_length), "^", r_old)
            l_new = function(i, k, r_new, xor_length) ^ r_old
            l_old = l_new
            r_old = r_new

            print("decrypted")
            print("l new:", l_new)
            print("r new:", r_new)
            print()

        l_int = l_new
        r_int = r_new
        if(i == 0):
            l_int_xor = create_iv(l_int) ^ l_int
            r_int_xor = create_iv(r_int) ^ r_int
        else:       #xor with last ciphertext
            l_int_xor = l_cipher ^ l_int
            r_int_xor = r_cipher & r_int

        decrypted_file.write(chr(l_int_xor))
        decrypted_file.write(chr(r_int_xor))

        #decrypted_file.write(int.to_bytes(l_new, length=len(l0_string), byteorder='big').decode('utf-8'))
        #decrypted_file.write(int.to_bytes(r_new, length=len(r0_string), byteorder='big').decode('utf-8'))

if __name__ == "__main__":
    main (sys.argv[1:])

