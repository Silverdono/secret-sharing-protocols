class LDEI:

    a = []
    e = -1
    z = []

    def __init__(self, a, e, z):
        self.a = a
        self.e = e
        self.z = z

    def __repr__(self) -> str:
        return "a = " + str(self.a) + ", e = " + str(self.e) + ", z = " + str(self.z)

    def __str__(self) -> str:
        return "{a = " + str(self.a) + ", e = " + str(self.e) + ", z = " + str(self.z) + "}"