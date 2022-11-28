import random

def gen_prime(a, b):
    def is_prime(num):
        if num == 2 or num == 3:
            return True
        if num % 2 == 0 or num<2:
            return False
        for n in range(3, int(num ** 0.5) + 1, 2):
            if num % n == 0:
                return False
        return True
    numbers = list(range(a, b + 1))
    random.shuffle(numbers)
    for n in numbers:
        if is_prime(n):
            return n
    raise Exception('Prime number not found in range')


class RSAKeygen:
    def __init__(self):
        self.d = None
        self.e = None
        self.fi = None
        self.n = None
        self.q = None
        self.p = None

    @staticmethod
    def nwd(a, b):
        while b:
            a, b = b, a % b
        return a
    # def nwd(a, b):
    #     if b == 0:
    #         r = a
    #         x = 1
    #         y = 0
    #         return r, x, y
    #     x2 = 1
    #     x1 = 0
    #     y2 = 0
    #     y1 = 1
    #     while b > 0:
    #         s = int(a / b)
    #         r = a - s * b
    #         x = x2 - s * x1
    #         y = y2 - a * y1
    #         a = b
    #         b = r
    #         x2 = x1
    #         x1 = x
    #         y2 = y1
    #         y1 = y
    #     r = a
    #     x = x2
    #     y = y2
    #     return r, x, y
    def generate(self):
        self.p = gen_prime(1000, 9999)
        self.q = self.p
        while self.p == self.q:
            self.q = gen_prime(1000, 9999)

        self.n = self.p * self.q
        self.fi = (self.p - 1) * (self.q - 1)
        self.e = self.generate_e()
        self.d = self.generate_d()

    def generate_e(self):
        es = list(range(3, self.fi))
        random.shuffle(es)
        for e in es:
            if RSAKeygen.nwd(e, self.fi) == 1:
                return e
        raise Exception('Cannot find e param')

    def generate_d(self):
        for d in list(range(3, self.fi)):
            if self.e * d % self.fi == 1:
                return d


if __name__ == "__main__":
    x = RSAKeygen()
    x.generate()
    with open('id_rsa.pub', 'w') as f:
        f.write(f'{x.n}\n{x.e}')

    with open('id_rsa', 'w') as f:
        f.write(f'{x.n}\n{x.d}')

    print('generated')