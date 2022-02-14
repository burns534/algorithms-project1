import math
import random;
def eratosthenes():
    n = random.randint(1, 1000)
    prime = [True for i in range(n + 1)]
    p = 2
    while (p * p <= n):
        if (prime[p] == True):
            for i in range(p ** 2, n + 1, p):
                prime[i] = False
        p += 1
    prime[0]= False
    prime[1]= False
    primesList = []
    for p in range(n + 1):
        if prime[p]:
            primesList.append(p)
    return (primesList[random.randint(0, len(primesList))], primesList[random.randint(0, len(primesList))])


def egcd(e,r):
    while(r!=0):
        e,r=r,e%r
    return e
 
#Euclid's Algorithm
def eugcd(e,r):
    for i in range(1,r):
        while(e!=0):
            a,b=r//e,r%e
            if(b!=0):
                print(".....")
            r=e
            e=b
 
#Extended Euclidean Algorithm
def eea(a,b):
    if(a%b==0):
        return(b,0,1)
    else:
        gcd,s,t = eea(b,a%b)
        s = s-((a//b) * t)
        return(gcd,t,s)
 
#Multiplicative Inverse
def mult_inv(e,r):
    gcd,s,_=eea(e,r)
    if(gcd!=1):
        return None
    elif(s == 1):
        return s%r

def get_encryption_key(n, r):
    e_list = []
    for i in range(1,n):
        if (egcd(i,r)==1):
            e_list.append(i)
    
    
    return e_list[random.randint(0, len(e_list) - 1)]

def get_decryption_key (e, r):
    return mult_inv(e,r)

def stringToAscii(text):
    ascii_values = []
    for character in text:
        ascii_values.append("{}".format(ord(character)))
    return ascii_values