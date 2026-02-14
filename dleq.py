class DLEQ:

    a = []
    e = -1
    z = -1

    def __init__(self, a, e, z):
        self.a = a
        self.e = e
        self.z = z

    def __repr__(self) -> str:
        return "a = " + str(self.a) + ", e = " + str(self.e) + ", z = " + str(self.z)

    def __str__(self) -> str:
        return "{a = " + str(self.a) + ", e = " + str(self.e) + ", z = " + str(self.z) + "}"
    
    def __eq__(self,dleq):
        if isinstance(dleq, DLEQ):
            return (self.a == dleq.a and self.e == dleq.e and self.z == dleq.z)
        else:
            return False