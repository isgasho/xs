// A golang translation of a 'Shakespeare insult generator'
// Originally from http://www.mainstrike.com/mstservices/handy/insult.html
package spinsult

import (
	"math/rand"
	"time"
)

var (
	r *rand.Rand

	phrase1 = [...]string{
		"artless", "bawdy", "beslubbering", "bootless", "churlish", "clouted",
		"cockered", "craven", "currish", "dankish", "dissembling", "droning", "errant", "fawning",
		"fobbing", "frothy", "froward", "gleeking", "goatish", "gorbellied", "impertinent",
		"infectious", "jarring", "loggerheaded", "lumpish", "mammering", "mangled", "mewling",
		"paunchy", "pribbling", "puking", "puny", "qualling", "rank", "reeky", "roguish", "ruttish",
		"saucy", "spleeny", "spongy", "surly", "tottering", "unmuzzled", "vain", "venomed",
		"villainous", "warped", "wayward", "weedy", "yeasty"}

	phrase2 = [...]string{"base-court", "bat-fowling", "beef-witted", "beetle-headed",
		"boil-brained", "clapper-clawed", "clay-brained", "common-kissing", "crook-pated",
		"dismal-dreaming", "dizzy-eyed", "doghearted", "dread-bolted", "earth-vexing",
		"elf-skinned", "fat-kidneyed", "fen-sucked", "flap-mouthed", "fly-bitten",
		"folly-fallen", "fool-born", "full-gorged", "guts-griping", "half-faced", "hasty-witted",
		"hedge-born", "hell-hated", "idle-headed", "ill-breeding", "ill-nurtured", "knotty-pated",
		"milk-livered", "motley-minded", "onion-eyed", "plume-plucked", "pottle-deep",
		"pox-marked", "reeling-ripe", "rough-hewn", "rude-growing", "rump-fed", "shard-borne",
		"sheep-biting", "spur-galled", "swag-bellied", "tardy-gaited", "tickle-brained",
		"toad-spotted", "urchin-snouted", "weather-bitten"}

	phrase3 = [...]string{"apple-john", "baggage", "barnacle", "bladder", "boar-pig", "bugbear",
		"bum-bailey", "canker-blossom", "clack-dish", "clotpole", "codpiece", "coxcomb", "death-token",
		"dewberry", "flap-dragon", "flax-wench", "flirt-gill", "foot-licker", "fustilarian",
		"giglet", "gudgeon", "haggard", "harpy", "hedge-pig", "horn-beast", "hugger-mugger",
		"joithead", "lewdster", "lout", "maggot-pie", "malt-worm", "mammet", "measle", "minnow",
		"miscreant", "moldwarp", "mumble-news", "nut-hook", "pigeon-egg", "pignut", "pumpion",
		"puttock", "ratsbane", "scut", "skainsmate", "strumpet", "varlet", "vassal", "wagtail",
		"whey-face"}
)

func GetSentence() (ret string) {
	return "Thou " + Get()
}

func Get() (ret string) {
	if r == nil {
		r = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	ret = phrase1[r.Int()%len(phrase1)] + " " +
		phrase2[r.Int()%len(phrase2)] + " " +
		phrase3[r.Int()%len(phrase3)] + "!"
	return
}
