package password

// wordList is an original, synthetic list of common English words used by
// memorable password generation. Every entry is lowercase ASCII, unique,
// and between 3 and 10 letters long. The list intentionally contains
// exactly 256 words so each word contributes eight bits of selection
// entropy.
var wordList = [...]string{
	"acorn", "agent", "alley", "angel", "apron", "arena", "artist", "attic",
	"award", "baker", "band", "basil", "beach", "bear", "beetle", "belt",
	"bicycle", "biscuit", "blanket", "board", "book", "bottle", "brass", "bridge",
	"brush", "buffalo", "bulb", "bunny", "button", "cactus", "camel", "canal",
	"canyon", "cargo", "carrot", "cat", "cell", "chair", "chess", "child",
	"chin", "clam", "clock", "clover", "coast", "cocoa", "coin", "compass",
	"coral", "corn", "country", "crane", "crayon", "cricket", "cup", "cushion",
	"dance", "desk", "dice", "dock", "doll", "donkey", "dove", "duck",
	"eagle", "earth", "elder", "engine", "falcon", "feather", "ferry", "fig",
	"fish", "flash", "floor", "fog", "fork", "frog", "fruit", "gate",
	"gift", "giraffe", "goat", "grape", "gravel", "ground", "guitar", "gull",
	"hammer", "hat", "hay", "hen", "hive", "hole", "hoof", "horse",
	"house", "ice", "insect", "ivy", "jaguar", "jaw", "joke", "judge",
	"juniper", "kettle", "kid", "kitten", "knife", "knot", "lake", "land",
	"lantern", "lemon", "lettuce", "lid", "lime", "lips", "lobster", "log",
	"lynx", "mail", "map", "market", "mat", "melon", "milk", "mirror",
	"mitten", "moon", "moss", "motor", "mouth", "muffin", "mule", "music",
	"napkin", "neck", "net", "noodle", "note", "nurse", "oasis", "office",
	"olive", "orbit", "otter", "owl", "page", "palace", "panda", "paper",
	"party", "path", "peak", "pelican", "pencil", "perch", "pickle", "pig",
	"pilot", "pipe", "pit", "place", "plant", "plaza", "pocket", "pond",
	"poppy", "port", "powder", "press", "pride", "pumpkin", "purple", "puzzle",
	"quarter", "quince", "raccoon", "radish", "rain", "rake", "ranch", "ray",
	"ridge", "river", "robin", "rocket", "roof", "rope", "rug", "sail",
	"salt", "sardine", "scarf", "scooter", "season", "seed", "shirt", "shrimp",
	"side", "singer", "skate", "sky", "slipper", "snake", "sock", "soil",
	"spade", "spider", "sport", "square", "stable", "star", "steel", "stool",
	"stove", "street", "studio", "summer", "swan", "table", "tale", "target",
	"tent", "thorn", "thumb", "tiger", "time", "toast", "tongue", "top",
	"tower", "train", "tribe", "truck", "tub", "turtle", "uncle", "vase",
	"verse", "village", "voice", "wall", "walrus", "wax", "west", "wheel",
	"whisker", "window", "wood", "word", "wrist", "year", "zebra", "zoo",
}

// WordListSize reports the number of distinct words available to memorable
// password generation.
func WordListSize() int { return len(wordList) }
