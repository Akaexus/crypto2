import pytest
from main import milionaires_problem


@pytest.mark.parametrize("bogus_money, apolonia_money, expected", [
    (100, 101,True ),
    (100, 100, True),
    (100, 99, False),
    (100, 98, False),
    (1,10000,True),
    (10000,1,False),
    (10000,100,False)
    ])
def test_milionaires_problem(bogus_money, apolonia_money, expected):
    assert milionaires_problem(bogus_money, apolonia_money) == expected
    
