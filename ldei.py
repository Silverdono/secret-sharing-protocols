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
    
    def __eq__(self,ldei):
        if isinstance(ldei, LDEI):
            return (self.a == ldei.a and self.e == ldei.e and self.z == ldei.z)
        else:
            return False