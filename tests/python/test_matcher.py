from Zorp.Core import *
from Zorp.Zorp import quit
from traceback import *

config.options.kzorp_enabled = FALSE

class SubstringMatcher(AbstractMatcher):
	def __init__(self, pattern = ""):
		AbstractMatcher.__init__(self)
		self.pattern = pattern
     
	def checkMatch(self, str):
		return (str.find(self.pattern) != -1)

def test(matcher_policy, str, should_accept):
	if matcher_policy.name:
		mname = matcher_policy.name
	else:
		mname = "(unnamed)"
	
	print "Testing str='", str, "', matcher='", mname, "', should_accept='", should_accept, "'"
	res = matcher_policy.matcher.checkMatch(str)
	if res == should_accept:
		print "Success"
	else:
		print "Failed"
		raise 'test error'

def init(name):
	try:
		a = MatcherPolicy("a", SubstringMatcher(pattern="a"))
		b = MatcherPolicy("b", SubstringMatcher(pattern="b"))
		c = MatcherPolicy("c", SubstringMatcher(pattern="c"))

		a_or_b = MatcherPolicy("a_or_b", CombineMatcher(expr=[Z_OR, "a", "b"]))
		a_or_b_or_c = MatcherPolicy("a_or_b_or_c", CombineMatcher(expr=[Z_OR, "a", "b", "c"]))
		not_a_or_b_and_c = MatcherPolicy("not_a_or_b_and_c", CombineMatcher( expr=[Z_AND, c, CombineMatcher(expr=[Z_NOT, a_or_b])] ))
		stacked_matcher = MatcherPolicy("stacked", CombineMatcher((Z_AND, c, (Z_NOT, a_or_b)) ))
		
		test(a, "alma", TRUE)
		test(a, "korte", FALSE)
		
		test(a_or_b, "alma", TRUE)
		test(a_or_b, "birskorte", TRUE)
		test(a_or_b, "birsalma", TRUE)
		test(a_or_b, "korte", FALSE)
		
		test(not_a_or_b_and_c, "korte", FALSE) # c missing
		test(not_a_or_b_and_c, "cseresznye", TRUE)
		test(not_a_or_b_and_c, "almaecet", FALSE) # a or b is true
		test(not_a_or_b_and_c, "borecet", FALSE) # a or b is true
		
		test(stacked_matcher, "korte", FALSE) # c missing
		test(stacked_matcher, "cseresznye", TRUE)
		test(stacked_matcher, "almaecet", FALSE) # a or b is true
		test(stacked_matcher, "borecet", FALSE) # a or b is true
		
		test(a_or_b_or_c, "korte", FALSE)
		test(a_or_b_or_c, "cseresznye", TRUE)
		test(a_or_b_or_c, "almaecet", TRUE)
		test(a_or_b_or_c, "borecet", TRUE)

	except Exception, e:
		print_exc()
		quit(1)
		return 1
		
	quit(0)
	return 1
