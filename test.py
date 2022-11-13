import pytest
from main import milionaires_problem


@pytest.mark.parametrize("bogus_money, apolonia_money, expected", [
    (100, 101,False ),
    (100, 100, False),
    (100, 99, True),
    (100, 98, True),
    (1,10000,False),
    (10000,1,True),
    (10000,100,True)
    ])
def test_milionaires_problem(bogus_money, apolonia_money, expected):
    assert milionaires_problem(bogus_money, apolonia_money) == expected
    
