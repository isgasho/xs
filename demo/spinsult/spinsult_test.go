//To show coverage for tests:
//
//1. go test -coverprofile=cov.out
//2. go tool cover -func=cov.out
//3. go tool cover -html=cov.out
//4. Profit!!
//
// For heatmap coverage, change step 1 to:
//2. go test -covermode=count -coverprofile=cov.out
//
// ref: https://blog.golang.org/cover

package spinsult

import (
	"fmt"
	"math/rand"
	"testing"
)

func Test1Get(t *testing.T) {
	//if testing.Short() {
	//	t.Skip("skipping test in short mode.")
	//}
	r = rand.New(rand.NewSource(42))
	out := Get()
	if out != "mammering doghearted codpiece!" {
		t.Fail()
	}
}

func Test2Get(t *testing.T) {
	//if testing.Short() {
	//	t.Skip("skipping test in short mode.")
	//}
	out := Get()
	if out != "dankish common-kissing coxcomb!" {
		t.Fail()
	}
	out = GetSentence()
	if out != "Thou wayward crook-pated fustilarian!" {
		t.Fail()
	}
}

// Example of calling Get() for a random insult.
func ExampleGet() {
	r = rand.New(rand.NewSource(42))
	out := GetSentence()
	fmt.Println(out)
	//Output: Thou mammering doghearted codpiece!
}
