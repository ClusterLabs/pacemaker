"""
A Python Singleton mixin class that makes use of some of the ideas
found at http://c2.com/cgi/wiki?PythonSingleton. Just inherit
from it and you have a singleton. No code is required in
subclasses to create singleton behavior -- inheritance from 
Singleton is all that is needed.

Singleton creation is threadsafe.

USAGE:

Just inherit from Singleton. If you need a constructor, include
an __init__() method in your class as you usually would. However,
if your class is S, you instantiate the singleton using S.getInstance() 
instead of S(). Repeated calls to S.getInstance() return the 
originally-created instance.

For example:

class S(Singleton):

    def __init__(self, a, b=1):
        pass
        
S1 = S.getInstance(1, b=3)


Most of the time, that's all you need to know. However, there are some
other useful behaviors. Read on for a full description:

1) Getting the singleton:

    S.getInstance() 
    
returns the instance of S. If none exists, it is created. 

2) The usual idiom to construct an instance by calling the class, i.e.

    S()
    
is disabled for the sake of clarity. 

For one thing, the S() syntax means instantiation, but getInstance()
usually does not cause instantiation. So the S() syntax would
be misleading.

Because of that, if S() were allowed, a programmer who didn't 
happen to notice the inheritance from Singleton (or who
wasn't fully aware of what a Singleton pattern
does) might think he was creating a new instance, 
which could lead to very unexpected behavior.

So, overall, it is felt that it is better to make things clearer
by requiring the call of a class method that is defined in
Singleton. An attempt to instantiate via S() will result 
in a SingletonException being raised.

3) Use __S.__init__() for instantiation processing,
since S.getInstance() runs S.__init__(), passing it the args it has received. 

If no data needs to be passed in at instantiation time, you don't need S.__init__().

4) If S.__init__(.) requires parameters, include them ONLY in the
first call to S.getInstance(). If subsequent calls have arguments,
a SingletonException is raised by default.

If you find it more convenient for subsequent calls to be allowed to
have arguments, but for those argumentsto be ignored, just include 
'ignoreSubsequent = True' in your class definition, i.e.:

  class S(Singleton):
  
      ignoreSubsequent = True

      def __init__(self, a, b=1):
          pass

5) For testing, it is sometimes convenient for all existing singleton
instances to be forgotten, so that new instantiations can occur. For that
reason, a forgetAllSingletons() function is included. Just call

  forgetAllSingletons()
  
and it is as if no earlier instantiations have occurred.

6) As an implementation detail, classes that inherit 
from Singleton may not have their own __new__
methods. To make sure this requirement is followed, 
an exception is raised if a Singleton subclass includ
es __new__. This happens at subclass instantiation
time (by means of the MetaSingleton metaclass.


By Gary Robinson, grobinson@flyfi.com. No rights reserved -- 
placed in the public domain -- which is only reasonable considering
how much it owes to other people's code and ideas which are in the
public domain. The idea of using a metaclass came from 
a  comment on Gary's blog (see 
http://www.garyrobinson.net/2004/03/python_singleto.html#comments). 
Other improvements came from comments and email from other
people who saw it online. (See the blog post and comments
for further credits.)

Not guaranteed to be fit for any particular purpose. Use at your
own risk. 
"""

import threading

class SingletonException(Exception):
    pass

_stSingletons = set()
_lockForSingletons = threading.RLock()
_lockForSingletonCreation = threading.RLock()   # Ensure only one instance of each Singleton
                                                # class is created.  This is not bound to the 
                                                # individual Singleton class since we need to
                                                # ensure that there is only one mutex for each
                                                # Singleton class, which would require having
                                                # a lock when setting up the Singleton class,
                                                # which is what this is anyway.  So, when any
                                                # Singleton is created, we lock this lock and
                                                # then we don't need to lock it again for that
                                                # class.

def _createSingletonInstance(cls, lstArgs, dctKwArgs):
    _lockForSingletonCreation.acquire()
    try:
        if cls._isInstantiated(): # some other thread got here first
            return 
        
        instance = cls.__new__(cls)
        try:
            instance.__init__(*lstArgs, **dctKwArgs)
        except TypeError, e:
            if e.message.find('__init__() takes') != -1:
                raise SingletonException, 'If the singleton requires __init__ args, supply them on first call to getInstance().' 
            else:
                raise
        cls.cInstance = instance
        _addSingleton(cls)
    finally:
        _lockForSingletonCreation.release()

def _addSingleton(cls):
    _lockForSingletons.acquire()
    try:
        assert cls not in _stSingletons
        _stSingletons.add(cls)
    finally:
        _lockForSingletons.release()

def _removeSingleton(cls):
    _lockForSingletons.acquire()
    try:
        if cls in _stSingletons:
            _stSingletons.remove(cls)
    finally:
        _lockForSingletons.release()

def forgetAllSingletons():
    '''This is useful in tests, since it is hard to know which singletons need to be cleared to make a test work.'''
    _lockForSingletons.acquire()
    try:
        for cls in _stSingletons.copy():
            cls._forgetClassInstanceReferenceForTesting()

        # Might have created some Singletons in the process of tearing down.
        # Try one more time - there should be a limit to this.
        iNumSingletons = len(_stSingletons)
        if len(_stSingletons) > 0:
            for cls in _stSingletons.copy():
                cls._forgetClassInstanceReferenceForTesting()
                iNumSingletons -= 1
                assert iNumSingletons == len(_stSingletons), 'Added a singleton while destroying ' + str(cls)
        assert len(_stSingletons) == 0, _stSingletons
    finally:
        _lockForSingletons.release()    

class MetaSingleton(type):
    def __new__(metaclass, strName, tupBases, dct):
        if dct.has_key('__new__'):
            raise SingletonException, 'Can not override __new__ in a Singleton'
        return super(MetaSingleton, metaclass).__new__(metaclass, strName, tupBases, dct)
        
    def __call__(cls, *lstArgs, **dictArgs):
        raise SingletonException, 'Singletons may only be instantiated through getInstance()'
        
class Singleton(object):
    __metaclass__ = MetaSingleton
    
    def getInstance(cls, *lstArgs, **dctKwArgs):
        """
        Call this to instantiate an instance or retrieve the existing instance.
        If the singleton requires args to be instantiated, include them the first
        time you call getInstance.        
        """
        if cls._isInstantiated():
            if (lstArgs or dctKwArgs) and not hasattr(cls, 'ignoreSubsequent'):
                raise SingletonException, 'Singleton already instantiated, but getInstance() called with args.'
        else:
            _createSingletonInstance(cls, lstArgs, dctKwArgs)
            
        return cls.cInstance
    getInstance = classmethod(getInstance)
    
    def _isInstantiated(cls):
        # Don't use hasattr(cls, 'cInstance'), because that screws things up if there is a singleton that
        # extends another singleton.  hasattr looks in the base class if it doesn't find in subclass.
        return 'cInstance' in cls.__dict__
    _isInstantiated = classmethod(_isInstantiated)

    # This can be handy for public use also
    isInstantiated = _isInstantiated

    def _forgetClassInstanceReferenceForTesting(cls):
        """
        This is designed for convenience in testing -- sometimes you 
        want to get rid of a singleton during test code to see what
        happens when you call getInstance() under a new situation.
        
        To really delete the object, all external references to it
        also need to be deleted.
        """
        try:
            if hasattr(cls.cInstance, '_prepareToForgetSingleton'):
                # tell instance to release anything it might be holding onto.
                cls.cInstance._prepareToForgetSingleton()
            del cls.cInstance
            _removeSingleton(cls)
        except AttributeError:
            # run up the chain of base classes until we find the one that has the instance
            # and then delete it there
            for baseClass in cls.__bases__: 
                if issubclass(baseClass, Singleton):
                    baseClass._forgetClassInstanceReferenceForTesting()
    _forgetClassInstanceReferenceForTesting = classmethod(_forgetClassInstanceReferenceForTesting)
    
    
if __name__ == '__main__':   

    import unittest
    import time
    
    class singletonmixin_Public_TestCase(unittest.TestCase):
        def testReturnsSameObject(self):
            """
            Demonstrates normal use -- just call getInstance and it returns a singleton instance
            """
        
            class A(Singleton): 
                def __init__(self):
                    super(A, self).__init__()
                    
            a1 = A.getInstance()
            a2 = A.getInstance()
            self.assertEquals(id(a1), id(a2))
            
        def testInstantiateWithMultiArgConstructor(self):
            """
            If the singleton needs args to construct, include them in the first
            call to get instances.
            """
                    
            class B(Singleton): 
                    
                def __init__(self, arg1, arg2):
                    super(B, self).__init__()
                    self.arg1 = arg1
                    self.arg2 = arg2
    
            b1 = B.getInstance('arg1 value', 'arg2 value')
            b2 = B.getInstance()
            self.assertEquals(b1.arg1, 'arg1 value')
            self.assertEquals(b1.arg2, 'arg2 value')
            self.assertEquals(id(b1), id(b2))
            
        def testInstantiateWithKeywordArg(self):
                    
            class B(Singleton): 
                    
                def __init__(self, arg1=5):
                    super(B, self).__init__()
                    self.arg1 = arg1
    
            b1 = B.getInstance('arg1 value')
            b2 = B.getInstance()
            self.assertEquals(b1.arg1, 'arg1 value')
            self.assertEquals(id(b1), id(b2))
            
        def testTryToInstantiateWithoutNeededArgs(self):
            
            class B(Singleton): 
                    
                def __init__(self, arg1, arg2):
                    super(B, self).__init__()
                    self.arg1 = arg1
                    self.arg2 = arg2
    
            self.assertRaises(SingletonException, B.getInstance)
            
        def testPassTypeErrorIfAllArgsThere(self):
            """
            Make sure the test for capturing missing args doesn't interfere with a normal TypeError.
            """
            class B(Singleton): 
                    
                def __init__(self, arg1, arg2):
                    super(B, self).__init__()
                    self.arg1 = arg1
                    self.arg2 = arg2
                    raise TypeError, 'some type error'
    
            self.assertRaises(TypeError, B.getInstance, 1, 2)
    
        def testTryToInstantiateWithoutGetInstance(self):
            """
            Demonstrates that singletons can ONLY be instantiated through
            getInstance, as long as they call Singleton.__init__ during construction.
            
            If this check is not required, you don't need to call Singleton.__init__().
            """
    
            class A(Singleton): 
                def __init__(self):
                    super(A, self).__init__()
                    
            self.assertRaises(SingletonException, A)
            
        def testDontAllowNew(self):
        
            def instantiatedAnIllegalClass():
                class A(Singleton): 
                    def __init__(self):
                        super(A, self).__init__()
                        
                    def __new__(metaclass, strName, tupBases, dct):
                        return super(MetaSingleton, metaclass).__new__(metaclass, strName, tupBases, dct)
                                        
            self.assertRaises(SingletonException, instantiatedAnIllegalClass)
        
        
        def testDontAllowArgsAfterConstruction(self):
            class B(Singleton): 
                    
                def __init__(self, arg1, arg2):
                    super(B, self).__init__()
                    self.arg1 = arg1
                    self.arg2 = arg2
    
            B.getInstance('arg1 value', 'arg2 value')
            self.assertRaises(SingletonException, B, 'arg1 value', 'arg2 value')
            
        def test_forgetClassInstanceReferenceForTesting(self):
            class A(Singleton): 
                def __init__(self):
                    super(A, self).__init__()
            class B(A): 
                def __init__(self):
                    super(B, self).__init__()
                    
            # check that changing the class after forgetting the instance produces
            # an instance of the new class
            a = A.getInstance()
            assert a.__class__.__name__ == 'A'
            A._forgetClassInstanceReferenceForTesting()
            b = B.getInstance()
            assert b.__class__.__name__ == 'B'
            
            # check that invoking the 'forget' on a subclass still deletes the instance
            B._forgetClassInstanceReferenceForTesting()
            a = A.getInstance()
            B._forgetClassInstanceReferenceForTesting()
            b = B.getInstance()
            assert b.__class__.__name__ == 'B'
    
        def test_forgetAllSingletons(self):
            # Should work if there are no singletons
            forgetAllSingletons()
    
            class A(Singleton):
                ciInitCount = 0
                def __init__(self):
                    super(A, self).__init__()
                    A.ciInitCount += 1
    
            A.getInstance()
            self.assertEqual(A.ciInitCount, 1)
    
            A.getInstance()
            self.assertEqual(A.ciInitCount, 1)
    
            forgetAllSingletons()
            A.getInstance()
            self.assertEqual(A.ciInitCount, 2)
    
        def test_threadedCreation(self):
            # Check that only one Singleton is created even if multiple
            #  threads try at the same time.  If fails, would see assert in _addSingleton
            class Test_Singleton(Singleton):
                def __init__(self):
                    super(Test_Singleton, self).__init__()
                
            class Test_SingletonThread(threading.Thread):
                def __init__(self, fTargetTime):
                    super(Test_SingletonThread, self).__init__()
                    self._fTargetTime = fTargetTime
                    self._eException = None
    
                def run(self):
                    try:
                        fSleepTime =  self._fTargetTime - time.time()
                        if fSleepTime > 0:
                            time.sleep(fSleepTime)
                        Test_Singleton.getInstance()
                    except Exception, e:
                        self._eException = e
                    
            fTargetTime = time.time() + 0.1
            lstThreads = []
            for _ in xrange(100):
                t = Test_SingletonThread(fTargetTime)
                t.start()
                lstThreads.append(t)
            eException = None
            for t in lstThreads:
                t.join()
                if t._eException and not eException:
                    eException = t._eException
            if eException:
                raise eException
    
        def testNoInit(self):
            """
            Demonstrates use with a class not defining __init__
            """
    
            class A(Singleton): 
                pass
                
                #INTENTIONALLY UNDEFINED:
                #def __init__(self):
                #    super(A, self).__init__()
    
            A.getInstance() #Make sure no exception is raised
            
        def testMultipleGetInstancesWithArgs(self):
    
            class A(Singleton):
            
                ignoreSubsequent = True
            
                def __init__(self, a, b=1):
                    pass
                    
            a1 = A.getInstance(1)
            a2 = A.getInstance(2) # ignores the second call because of ignoreSubsequent
                
            class B(Singleton):
            
                def __init__(self, a, b=1):
                    pass
                    
            b1 = B.getInstance(1)
            self.assertRaises(SingletonException, B.getInstance, 2) # No ignoreSubsequent included
    
            class C(Singleton):
            
                def __init__(self, a=1):
                    pass
                    
            c1 = C.getInstance(a=1)
            self.assertRaises(SingletonException, C.getInstance, a=2) # No ignoreSubsequent included
        
        def testInheritance(self):
            """ 
            It's sometimes said that you can't subclass a singleton (see, for instance,
            http://steve.yegge.googlepages.com/singleton-considered-stupid point e). This
            test shows that at least rudimentary subclassing works fine for us.
            """
    
            class A(Singleton):
            
                def setX(self, x):
                    self.x = x
                    
                def setZ(self, z):
                    raise NotImplementedError
                    
            class B(A):
                
                def setX(self, x):
                    self.x = -x
                    
                def setY(self, y):
                    self.y = y
                    
            a = A.getInstance()
            a.setX(5)
            b = B.getInstance()
            b.setX(5)
            b.setY(50)
            self.assertEqual((a.x, b.x, b.y), (5, -5, 50))
            self.assertRaises(AttributeError, eval, 'a.setY', {}, locals())
            self.assertRaises(NotImplementedError, b.setZ, 500)

    unittest.main()
    
# vim:ts=4:sw=4:et:
