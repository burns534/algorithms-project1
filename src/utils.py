def extended_gcd(a=1, b=1):
    ''' The extended_gcd function implements the
    extension of Euclid's GCD algorithm to find integers x and y
    such that ax + by = gcd(a, b) '''
    if b == 0:
        return (1, 0, a)
    (x, y, d) = extended_gcd(b, a % b)
    return y, x - a // b * y, d

