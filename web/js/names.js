// Funny alliterative server name generator
// Generates names like: devbox-peculiar-potato, devbox-wacky-walrus

const words = {
    b: { adj: ['bouncy', 'bubbly', 'brave', 'bashful'], nouns: ['banana', 'badger', 'biscuit', 'buffalo'] },
    c: { adj: ['cosmic', 'crafty', 'cuddly', 'curious'], nouns: ['cactus', 'cloud', 'cookie', 'cucumber'] },
    d: { adj: ['dapper', 'dizzy', 'dazzling', 'dreamy'], nouns: ['dolphin', 'donut', 'dragon', 'dumpling'] },
    f: { adj: ['fluffy', 'funky', 'fierce', 'fancy'], nouns: ['falcon', 'flamingo', 'frog', 'fudge'] },
    g: { adj: ['gleeful', 'groovy', 'gentle', 'goofy'], nouns: ['gopher', 'giraffe', 'grape', 'gnome'] },
    h: { adj: ['happy', 'hungry', 'hasty', 'humble'], nouns: ['hamster', 'hippo', 'hedgehog', 'hotdog'] },
    j: { adj: ['jolly', 'jazzy', 'jumpy', 'jaunty'], nouns: ['jellyfish', 'jackrabbit', 'jaguar', 'jelly'] },
    l: { adj: ['lively', 'lucky', 'lazy', 'lumpy'], nouns: ['llama', 'lemur', 'lobster', 'lemon'] },
    m: { adj: ['mighty', 'mellow', 'magical', 'mischievous'], nouns: ['mango', 'moose', 'muffin', 'mushroom'] },
    n: { adj: ['nifty', 'nimble', 'nutty', 'noble'], nouns: ['narwhal', 'noodle', 'newt', 'nugget'] },
    p: { adj: ['peculiar', 'plucky', 'peppy', 'puzzled'], nouns: ['potato', 'penguin', 'panda', 'pickle'] },
    q: { adj: ['quirky', 'quaint', 'quick', 'quiet'], nouns: ['quokka', 'quail', 'quiche', 'quartz'] },
    r: { adj: ['rowdy', 'rusty', 'radiant', 'rambunctious'], nouns: ['raccoon', 'raven', 'radish', 'robot'] },
    s: { adj: ['silly', 'sneaky', 'sassy', 'sparkly'], nouns: ['squid', 'sloth', 'salmon', 'sandwich'] },
    t: { adj: ['tipsy', 'tricky', 'tubby', 'tropical'], nouns: ['turtle', 'taco', 'toucan', 'turnip'] },
    w: { adj: ['wacky', 'wiggly', 'wild', 'whimsical'], nouns: ['walrus', 'waffle', 'wombat', 'wizard'] },
    z: { adj: ['zany', 'zippy', 'zealous', 'zesty'], nouns: ['zebra', 'zucchini', 'zombie', 'zeppelin'] }
};

const letters = Object.keys(words);

function randomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

export function generateServerName() {
    const letter = randomElement(letters);
    const adj = randomElement(words[letter].adj);
    const noun = randomElement(words[letter].nouns);
    return `devbox-${adj}-${noun}`;
}
