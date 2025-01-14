from abc import ABC, abstractmethod


class Check(ABC):
    @abstractmethod
    def check(self, packet):
        pass
