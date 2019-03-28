#!/bin/sh
#if 0
./$(dirname "$0")/_testrunner.sh "$0" <<EOF
#endif

#if 00
@@ -96,19 +96,19 @@ void zob2(int ***z) {
 }
 
 void bar0(void) {
-	int i;
+	int i/*FIXME:initialize me*/;
 	foo(&i);
 	baz(i);
 }
 
 void bar1(void) {
-	int i;
+	int i/*FIXME:initialize me*/;
 	foo(&i);
 	foo(&i);
 }
 
 void bar2(void) {
-	int a = 1, b, c = 3;
+	int a = 1, b/*FIXME:initialize me*/, c = 3;
 	foo(&a);
 	baz(a);
 	foo(&b);
@@ -118,37 +118,37 @@ void bar2(void) {
 }
 
 void bar3(int *w) {
-	int i;
+	int i/*FIXME:initialize me*/;
 	foo(&i);
 	*w = i;
 }
 
 void bar4(int **w) {
-	int i;
+	int i/*FIXME:initialize me*/;
 	foo(&i);
 	**w = *i;
 }
 
 void bar5(int ***w) {
-	int *i;
+	int *i/*FIXME:initialize me*/;
 	zob(&i);
 	***w = *i;
 }
 
 void bar6(int ***w) {
-	int *i;
+	int *i/*FIXME:initialize me*/;
 	zob1(&i);
 	***w = *i;
 }
 
 void bar7(int ****w) {
-	int **i;
+	int **i/*FIXME:initialize me*/;
 	zob1(&i);
 	****w = **i;
 }
 
 int bar8(void) {
-	int i;
+	int i/*FIXME:initialize me*/;
 	foo(&i);
 	return i;
 }
@@ -166,7 +166,7 @@ void not1(void) {
 
 /* XXX false positive */
 void not2(void) {
-	int i;
+	int i/*FIXME:initialize me*/;
 	foo(&i);
 	*(&i) = 2;
 }
#else

void foo(int *z) {
	return:
}
void baz(int z) {
	return;
}
void zob1(int **z) {
	return;
}
void zob2(int ***z) {
	return;
}

void bar0(void) {
	int i;
	foo(&i);
	baz(i);
}

void bar1(void) {
	int i;
	foo(&i);
	foo(&i);
}

void bar2(void) {
	int a = 1, b, c = 3;
	foo(&a);
	baz(a);
	foo(&b);
	baz(b);
	foo(&c);
	baz(c);
}

void bar3(int *w) {
	int i;
	foo(&i);
	*w = i;
}

void bar4(int **w) {
	int i;
	foo(&i);
	**w = *i;
}

void bar5(int ***w) {
	int *i;
	zob(&i);
	***w = *i;
}

void bar6(int ***w) {
	int *i;
	zob1(&i);
	***w = *i;
}

void bar7(int ****w) {
	int **i;
	zob1(&i);
	****w = **i;
}

int bar8(void) {
	int i;
	foo(&i);
	return i;
}

void not0(void) {
	int i;
	foo(&i);
}

void not1(void) {
	int i;
	foo(&i);
	i = 1;
}

/* XXX false positive */
void not2(void) {
	int i;
	foo(&i);
	*(&i) = 2;
}
#endif

#if 0
EOF
#endif
