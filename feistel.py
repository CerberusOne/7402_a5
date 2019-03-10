#!/usr/bin/python3.5

import sys, argparse, textwrap, math

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


    blocks = [''] * math.ceil((len(plaintext)/2))
    
    #open file to write ciphertext
    cipher_file = open("results.txt", "w+")

    #split into blocks for CBC/CTR
    y = 0   #counter for blocks array

    for x in range(0, len(plaintext)-1, 2):
        print("plain|x:", len(plaintext), y)
        blocks[y] = plaintext[x]
        print("plaintext:", plaintext[x])
        blocks[y] += plaintext[x+1]
        print("plaintext:", plaintext[x+1])
        y += 1

    #add last character
        #and add white space if odd num of char
    if len(plaintext) %2 == 1:
        print("odd number of plaintext characters")
        print("plaintext:", plaintext[len(plaintext)-1])
        blocks[y] = plaintext[len(plaintext)-1]
        blocks[y] += ' '


    #blocks = textwrap.wrap(plaintext, 2, replace_whitespace = False)

    #fix any mistakes from textwrap (not registering spaces properly)
        #and pad if there are an odd number of characters
    '''
    for x in range(len(blocks)):
        if blocks[x][1:] == '':
            blocks[x] += ' '
            print("space found")
    '''


    print("blocks:", blocks)

    blocks_cipher = [[0 for x in range(2)] for y in range(len(blocks))]
    print("blocks_cipher:", blocks_cipher)

    
    #set default IV for first block
    iv = ord("a")
    l_iv = iv
    r_iv = iv

    print("ENCRYPTING")
    print()

    #iterate through every block in plaintext (2 char each)
    for block_num in range(0, len(blocks)):
        print("BLOCK", block_num, "--------")
        print()

        #set current block
        curr_block = blocks[block_num]

        if blocks[block_num][:1] == '':
            blocks[block_num] += ' '
        if blocks[block_num][1:] == '':
            blocks[block_num] += ' '

        #set left and right sides
        l = blocks[block_num][:1]
        r = blocks[block_num][1:]

        print("l:", l, "(", ord(l), ")")
        print("r:", r, "(", ord(r), ")")
        print()

        #set IV to default if first block, otherwise use last ciphertext and xor
        if block_num == 0:
            l_iv = iv
            r_iv = iv


        #xor left side with last left ciphertext
        l_int = ord(l) ^ l_iv
        #xor right side with last right ciphertext
        r_int = ord(r) ^ r_iv

        print("xoring plaintext and IV")
        print("l ^ iv:", l_int)
        print("r ^ iv:", r_int)
        print()

        #set values of the initial l and r sides
        l_old = l_int
        r_old = r_int
        
        #encrypt with function for ~8 rounds with the feistel cipher
        for round_num in range(0, iterations):
            print("ROUND", round_num)

            #move r old to l new
            l_new = r_old

            #find length of r
            xor_length = len(str(abs(r_old)))
            
            #xor l old with f(r old, k)
            r_new = function(round_num, k, r_old, xor_length) ^ l_old

            print("encrypting")
            print("l_new:", l_new)
            print("r_new:", r_new)
            print()

            #update nanmes for next iteration
            l_old = l_new
            r_old = r_new

        blocks_cipher[block_num][0] = l_new
        blocks_cipher[block_num][1] = r_new
        print("blocks_cipher:", blocks_cipher)

        #set next ciphertext block
        if(block_num < (len(blocks) - 1)):
            l_iv = l_new
            r_iv = r_new
            print("Set new iv: ", l_iv, "|", r_iv)
        else:
            print("Not setting new iv: ", l_iv, "|", r_iv)

            
    '''
    cipher_file.write(str(l_new))
    cipher_file.write(str(r_new))
    cipher_file.close()
    ''' 

    blocks_decrypt = [''] * len(blocks)
    
    #decrypt
    print("========DECRYPTING========")
    print()

    #iterate through every block in ciphertext
    for block_num in range(len(blocks)-1, 0-1, -1):
        print("BLOCK", block_num, "--------")
        print()

        l_old = blocks_cipher[block_num][0]
        r_old = blocks_cipher[block_num][1]

        #print original ints
        print("l:", l_old)
        print("r:", r_old)
        print()

        #decrypt feistel cipher ~8 rounds
        for round_num in range(iterations-1, 0-1, -1):
            print("ROUND", round_num)

            #r new is last round's l
            r_new = l_old
            
            #find length of l
            xor_length = len(str(abs(r_new)))
            
            #xor r old with f(r new, k)
            l_new = function(round_num, k, r_new, xor_length) ^ r_old
            
            print("decrypting function xor r_old")
            print("l new:", l_new)
            print("r new:", r_new)
            print()

            #update names for next iteration
            l_old = l_new
            r_old = r_new
        
        #set IV to default if first block
        if block_num == 0:
            l_iv = iv
            r_iv = iv
            print("Using default iv:", l_iv, "|", r_iv)
        else:
            l_iv = blocks_cipher[block_num-1][0]
            r_iv = blocks_cipher[block_num-1][1]
            print("Set new iv:", l_iv, "|", r_iv)

        #xor left side with IV
        l_new = l_new ^ l_iv

        #xor right side with IV
        r_new = r_new ^ r_iv

        blocks_decrypt[block_num] = chr(l_new)
        blocks_decrypt[block_num] += chr(r_new)

        print("decrypted:")
        print("l:", chr(l_new), "(", l_new, ")")
        print("r:", chr(r_new), "(", r_new, ")")
        print()

    #remove padding if added earlier
    if blocks_decrypt[len(blocks)-1][1:] == ' ':
        blocks_decrypt[len(blocks)-1] = blocks_decrypt[len(blocks)-1][:1]

    print("RESULTS:")
    print(blocks_decrypt)

    #write results to file
    decrypted_file = open("decrypted_results.txt", "w+")
    for x in range(len(blocks_decrypt)):
        decrypted_file.write(blocks_decrypt[x])


if __name__ == "__main__":
    main (sys.argv[1:])

