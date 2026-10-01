// =========================================================
// ENCRYPTO MODERATION ENGINE
// =========================================================
//
// Context-aware client-side risk detection.
//
// IMPORTANT:
// This system does NOT block messages.
// It detects potentially dangerous content and
// attaches a risk level.
//
// Levels:
// NONE
// LOW
// MEDIUM
// HIGH
// CRITICAL
//
// The goal is to reduce false positives by understanding
// common fictional / educational / news contexts.
//
// Examples:
//
// "I watched a movie about a bomb"
//              -> NONE
//
// "I saw a knife in a movie"
//              -> NONE
//
// "This game has guns"
//              -> NONE
//
// "I have a knife"
//              -> MEDIUM
//
// "I have a bomb"
//              -> HIGH
//
// "I am going to kill him"
//              -> CRITICAL
//
// "Bring the knife and attack him"
//              -> HIGH
// =========================================================


// =========================================================
// RISK LEVEL ORDER
// =========================================================

const LEVEL_ORDER = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};


// =========================================================
// CONTEXT DEFINITIONS
// =========================================================
//
// These contexts commonly describe fictional,
// educational, historical, journalistic, or media content.
//
// They should reduce false positives for isolated
// sensitive words.
//
// Example:
//
// "I watched a movie about a bomb"
// "The movie had a knife"
// "This game contains guns"
// "I read an article about terrorism"
//
// These are not automatically treated as threats.
//

const BENIGN_CONTEXT_PATTERNS = [

  // -------------------------------------------------------
  // MOVIES / FILMS / TV
  // -------------------------------------------------------

  /\b(?:movie|film|films|show|series|episode|documentary|documentary film)\b/i,

  /\b(?:watched|watching|saw|seen)\b.{0,60}\b(?:movie|film|show|series|episode)\b/i,

  /\b(?:movie|film|show|series|episode)\b.{0,80}\b(?:about|with|containing|contains|had|has|scene|scenes)\b/i,


  // -------------------------------------------------------
  // GAMES
  // -------------------------------------------------------

  /\b(?:game|gaming|video game|videogame|gameplay|mission|level|character)\b/i,

  /\b(?:played|playing)\b.{0,60}\b(?:game|games)\b/i,


  // -------------------------------------------------------
  // BOOKS / STORIES / FICTION
  // -------------------------------------------------------

  /\b(?:book|novel|story|stories|fiction|chapter|comic|comics|manga)\b/i,

  /\b(?:character|characters|protagonist|villain|fictional)\b/i,

  /\b(?:read|reading)\b.{0,80}\b(?:book|novel|story|article|chapter)\b/i,


  // -------------------------------------------------------
  // NEWS / JOURNALISM
  // -------------------------------------------------------

  /\b(?:news|newspaper|article|report|reporting|journalist|journalism)\b/i,

  /\b(?:headline|headlines|documented|reported|according to)\b/i,


  // -------------------------------------------------------
  // HISTORY / EDUCATION
  // -------------------------------------------------------

  /\b(?:history|historical|history class|school|college|university|lecture|lesson)\b/i,

  /\b(?:studied|study|studying|learned|learning|research|researching)\b/i,

  /\b(?:exam|assignment|homework|textbook|academic|educational)\b/i,


  // -------------------------------------------------------
  // DISCUSSION / EXPLANATION
  // -------------------------------------------------------

  /\b(?:discuss|discussion|discussing|explain|explaining|meaning|definition)\b/i,

  /\b(?:what does|what is|what are|tell me about|information about)\b/i,


  // -------------------------------------------------------
  // FICTIONAL LANGUAGE
  // -------------------------------------------------------

  /\b(?:fictional|imaginary|fantasy|fantasy story|roleplay|role-play|role playing)\b/i,

  /\b(?:pretend|pretending|hypothetical|hypothetically)\b/i,

];


// =========================================================
// STRONG BENIGN PHRASES
// =========================================================
//
// These are stronger signals that a sensitive word is
// being discussed rather than used as an actual threat.
//
// Example:
//
// "I watched a movie about a bomb"
// "I saw a bomb in a movie"
// "The movie had a knife"
// "The game has guns"
//
// These should remain unflagged unless there is also
// a clear direct-threat pattern.
//

const STRONG_BENIGN_CONTEXT_PATTERNS = [

  // -------------------------------------------------------
  // MOVIE + SENSITIVE CONTENT
  // -------------------------------------------------------

  /\b(?:watched|watching|saw|seen)\b.{0,80}\b(?:movie|film|show|series|episode)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b/i,

  /\b(?:movie|film|show|series|episode)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b/i,

  /\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b.{0,100}\b(?:movie|film|show|series|episode)\b/i,


  // -------------------------------------------------------
  // GAME + SENSITIVE CONTENT
  // -------------------------------------------------------

  /\b(?:game|gaming|gameplay|video game)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b/i,

  /\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b.{0,100}\b(?:game|gaming|gameplay|video game)\b/i,


  // -------------------------------------------------------
  // BOOK / STORY + SENSITIVE CONTENT
  // -------------------------------------------------------

  /\b(?:book|novel|story|fiction|chapter|comic|manga)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b/i,

  /\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion)\b.{0,100}\b(?:book|novel|story|fiction|chapter|comic|manga)\b/i,


  // -------------------------------------------------------
  // NEWS / ARTICLE + SENSITIVE CONTENT
  // -------------------------------------------------------

  /\b(?:news|article|report|newspaper|journalist|journalism)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion|terrorism)\b/i,

  /\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|explosion|terrorism)\b.{0,100}\b(?:news|article|report|newspaper|journalist|journalism)\b/i,


  // -------------------------------------------------------
  // HISTORICAL / EDUCATIONAL CONTENT
  // -------------------------------------------------------

  /\b(?:history|historical|school|college|university|lecture|lesson|research|studied|study|textbook)\b.{0,100}\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|war|terrorism)\b/i,

  /\b(?:bomb|knife|gun|weapon|shoot|kill|attack|murder|war|terrorism)\b.{0,100}\b(?:history|historical|school|college|university|lecture|lesson|research|studied|study|textbook)\b/i,

];


// =========================================================
// CRITICAL RULES
// =========================================================
//
// These are explicit first-person threats.
//
// These ALWAYS take priority over benign context.
//
// Example:
//
// "I am going to kill him"
// "I will shoot you"
// "I plan to stab him"
//
// These should remain CRITICAL.
//

const CRITICAL_RULES = [

  {
    level: "CRITICAL",

    category: "DIRECT_THREAT",

    score: 100,

    reason:
      "Direct violent threat detected.",

    patterns: [

      // I am going to kill...
      /\bi\s*(?:am|'m)\s+going\s+to\s+(?:kill|murder|stab|shoot|attack|hurt)\b/i,

      // I will kill...
      /\bi\s+will\s+(?:kill|murder|stab|shoot|attack|hurt)\b/i,

      // I'll kill...
      /\bi(?:'ll| will)\s+(?:kill|murder|stab|shoot|attack|hurt)\b/i,

      // I plan to kill...
      /\bi\s+(?:plan|intend)\s+to\s+(?:kill|murder|stab|shoot|attack|hurt)\b/i,

      // Going to kill...
      /\b(?:going\s+to|plan\s+to|intend\s+to)\s+(?:kill|murder|stab|shoot)\b/i,

      // Direct threat against recipient
      /\bi\s+(?:am|'m)\s+going\s+to\s+(?:hurt|harm)\s+you\b/i,

      /\bi\s+will\s+(?:hurt|harm)\s+you\b/i,

      /\bi(?:'ll| will)\s+(?:kill|hurt|harm|shoot|stab)\s+you\b/i,

    ],
  },

];


// =========================================================
// HIGH-RISK RULES
// =========================================================
//
// These indicate violent action or potentially dangerous
// activity.
//
// Unlike the previous version, isolated words such as
// "bomb" are NOT enough to trigger HIGH.
//
// They need stronger action / possession / intent context.
//
// This reduces false positives.
//

const HIGH_RULES = [

  // -------------------------------------------------------
  // POSSESSION / ACCESS
  // -------------------------------------------------------

  {
    level: "HIGH",

    category: "VIOLENCE",

    score: 70,

    reason:
      "Potential violent intent or dangerous activity detected.",

    patterns: [

      /\bi\s+(?:have|got|got a|own|possess)\s+(?:a\s+)?(?:bomb|explosive|grenade)\b/i,

      /\b(?:have|got|own|possess)\s+(?:a\s+)?(?:bomb|explosive|grenade)\b/i,

      /\bthere\s+is\s+(?:a\s+)?(?:bomb|explosive|grenade)\s+(?:here|inside|in)\b/i,

      /\b(?:placed|planted|left)\s+(?:a\s+)?(?:bomb|explosive|grenade)\b/i,

    ],
  },


  // -------------------------------------------------------
  // EXPLOSIVE ACTION
  // -------------------------------------------------------

  {
    level: "HIGH",

    category: "VIOLENCE",

    score: 70,

    reason:
      "Potential violent intent or dangerous activity detected.",

    patterns: [

      /\b(?:blow\s+up|set\s+off|detonate|detonation)\b/i,

      /\b(?:explode|exploding|exploded)\s+(?:it|this|that|the)\b/i,

      /\b(?:plant|planted|planting)\s+(?:a\s+)?(?:bomb|explosive)\b/i,

      /\b(?:detonate|detonating)\s+(?:a\s+)?(?:bomb|explosive)\b/i,

    ],
  },


  // -------------------------------------------------------
  // ATTACK ACTION
  // -------------------------------------------------------

  {
    level: "HIGH",

    category: "VIOLENCE",

    score: 70,

    reason:
      "Violent action or intent detected.",

    patterns: [

      /\b(?:attack|attacking|attacked)\s+(?:you|him|her|them|someone|people)\b/i,

      /\b(?:kill|murder|assassinate|execute)\s+(?:you|him|her|them|someone|people)\b/i,

      /\b(?:stab|stabbing|stabbed)\s+(?:you|him|her|them|someone|people)\b/i,

      /\b(?:shoot|shooting|shot)\s+(?:you|him|her|them|someone|people)\b/i,

    ],
  },


  // -------------------------------------------------------
  // EXPLICIT THREAT CONTEXT
  // -------------------------------------------------------

  {
    level: "HIGH",

    category: "THREAT_CONTEXT",

    score: 70,

    reason:
      "Threat-related language detected.",

    patterns: [

      /\b(?:hurt|harm|destroy)\s+(?:you|him|her|them|someone)\b/i,

      /\b(?:make|want)\s+(?:you|him|her|them)\s+(?:pay|suffer)\b/i,

      /\b(?:take|bring)\s+(?:a\s+)?(?:gun|knife|weapon)\b/i,

      /\b(?:bring|get|grab)\s+(?:a\s+)?(?:gun|knife|weapon)\b/i,

    ],
  },


  // -------------------------------------------------------
  // DIRECT COMBINATION OF WEAPON + ATTACK
  // -------------------------------------------------------

  {
    level: "HIGH",

    category: "VIOLENCE",

    score: 75,

    reason:
      "Weapon and violent action detected together.",

    patterns: [

      /\b(?:gun|knife|weapon|blade|rifle|pistol)\b.{0,60}\b(?:attack|shoot|stab|kill|hurt)\b/i,

      /\b(?:attack|shoot|stab|kill|hurt)\b.{0,60}\b(?:gun|knife|weapon|blade|rifle|pistol)\b/i,

    ],
  },

];


// =========================================================
// MEDIUM-RISK RULES
// =========================================================
//
// These identify weapon-related language when it appears
// to refer to a real object or personal possession.
//
// A simple mention inside media / education context will
// not normally trigger these rules.
//

const MEDIUM_RULES = [

  {
    level: "MEDIUM",

    category: "WEAPON",

    score: 35,

    reason:
      "Weapon-related terminology detected.",

    patterns: [

      // Personal possession
      /\bi\s+(?:have|got|own|carry|carrying)\s+(?:a\s+)?(?:knife|knives|blade|dagger)\b/i,

      /\bi\s+(?:have|got|own|carry|carrying)\s+(?:a\s+)?(?:gun|pistol|rifle|firearm)\b/i,

      /\bi\s+(?:have|got|own|carry|carrying)\s+(?:a\s+)?(?:weapon|grenade|explosive|ammunition)\b/i,


      // Imperative / acquisition
      /\b(?:bring|get|take|carry|grab)\s+(?:a\s+)?(?:knife|gun|weapon|pistol|rifle|blade)\b/i,


      // Generic real-world possession
      /\b(?:my|your)\s+(?:knife|gun|weapon|pistol|rifle|blade|firearm)\b/i,

    ],
  },

];


// =========================================================
// LOW-RISK RULES
// =========================================================
//
// Sensitive terminology alone is not treated as a threat.
//
// These are useful for recording potentially sensitive
// conversations without generating aggressive warnings.
//

const LOW_RULES = [

  {
    level: "LOW",

    category: "SENSITIVE_TERM",

    score: 15,

    reason:
      "Potentially sensitive terminology detected.",

    patterns: [

      /\bviolence\b/i,

      /\bviolent\b/i,

      /\bweaponry\b/i,

      /\bhostage(?:s)?\b/i,

      /\bwar\b/i,

      /\bcombat\b/i,

      /\bmilitant\b/i,

      /\bterrorism\b/i,

      /\bterrorist\b/i,

    ],
  },

];


// =========================================================
// ALL RULES
// =========================================================

const RULES = [
  ...CRITICAL_RULES,
  ...HIGH_RULES,
  ...MEDIUM_RULES,
  ...LOW_RULES,
];


// =========================================================
// NORMALIZE TEXT
// =========================================================

function normalizeText(
  text
) {
  return String(
    text || ""
  )
    .normalize("NFKC")
    .toLowerCase()
    .replace(
      /[\u200B-\u200D\uFEFF]/g,
      ""
    )
    .replace(
      /\s+/g,
      " "
    )
    .trim();
}


// =========================================================
// TEST BENIGN CONTEXT
// =========================================================

function hasBenignContext(
  normalized
) {
  return BENIGN_CONTEXT_PATTERNS.some(
    (pattern) =>
      pattern.test(
        normalized
      )
  );
}


// =========================================================
// TEST STRONG BENIGN CONTEXT
// =========================================================

function hasStrongBenignContext(
  normalized
) {
  return STRONG_BENIGN_CONTEXT_PATTERNS.some(
    (pattern) =>
      pattern.test(
        normalized
      )
  );
}


// =========================================================
// TEST CRITICAL RULES
// =========================================================
//
// Critical rules are evaluated FIRST.
//
// A direct threat must not disappear merely because
// another word such as "movie" appears in the sentence.
//

function getCriticalMatches(
  normalized
) {
  return CRITICAL_RULES.filter(
    (rule) =>
      rule.patterns.some(
        (pattern) =>
          pattern.test(
            normalized
          )
      )
  );
}


// =========================================================
// TEST HIGH RULES
// =========================================================

function getHighMatches(
  normalized
) {
  return HIGH_RULES.filter(
    (rule) =>
      rule.patterns.some(
        (pattern) =>
          pattern.test(
            normalized
          )
      )
  );
}


// =========================================================
// TEST MEDIUM RULES
// =========================================================

function getMediumMatches(
  normalized
) {
  return MEDIUM_RULES.filter(
    (rule) =>
      rule.patterns.some(
        (pattern) =>
          pattern.test(
            normalized
          )
      )
  );
}


// =========================================================
// TEST LOW RULES
// =========================================================

function getLowMatches(
  normalized
) {
  return LOW_RULES.filter(
    (rule) =>
      rule.patterns.some(
        (pattern) =>
          pattern.test(
            normalized
          )
      )
  );
}


// =========================================================
// GET STRONGEST RULE
// =========================================================

function getStrongestRule(
  matches
) {
  if (
    !matches.length
  ) {
    return null;
  }

  return matches.reduce(
    (best, rule) => {

      if (
        !best
      ) {
        return rule;
      }

      return LEVEL_ORDER[
        rule.level
      ] >
        LEVEL_ORDER[
          best.level
        ]
        ? rule
        : best;
    },
    null
  );
}


// =========================================================
// ANALYZE MESSAGE
// =========================================================

export function analyzeMessage(
  text
) {

  // -------------------------------------------------------
  // NORMALIZE
  // -------------------------------------------------------

  const normalized =
    normalizeText(
      text
    );


  // -------------------------------------------------------
  // EMPTY MESSAGE
  // -------------------------------------------------------

  if (
    !normalized
  ) {
    return {
      flagged: false,

      level: "NONE",

      category: "",

      reason: "",

      score: 0,
    };
  }


  // =======================================================
  // STEP 1
  // CRITICAL DIRECT THREATS
  // =======================================================
  //
  // These always win.
  //

  const criticalMatches =
    getCriticalMatches(
      normalized
    );


  if (
    criticalMatches.length
  ) {

    const strongest =
      getStrongestRule(
        criticalMatches
      );

    return {
      flagged: true,

      level:
        strongest.level,

      category:
        strongest.category,

      reason:
        strongest.reason,

      score:
        strongest.score,
    };
  }


  // =======================================================
  // STEP 2
  // STRONG BENIGN CONTEXT
  // =======================================================
  //
  // If the message clearly describes a movie, game,
  // book, article, historical event, etc., do not flag
  // isolated sensitive terminology.
  //
  // Example:
  //
  // "I watched a movie of bomb"
  //
  // -> NONE
  //
  // However, this happens AFTER critical detection,
  // so direct threats remain protected.
  //

  const strongBenign =
    hasStrongBenignContext(
      normalized
    );


  // =======================================================
  // STEP 3
  // HIGH-RISK RULES
  // =======================================================

  const highMatches =
    getHighMatches(
      normalized
    );


  if (
    highMatches.length
  ) {

    const strongest =
      getStrongestRule(
        highMatches
      );

    return {
      flagged: true,

      level:
        strongest.level,

      category:
        strongest.category,

      reason:
        strongest.reason,

      score:
        strongest.score,
    };
  }


  // =======================================================
  // STEP 4
  // MEDIUM-RISK RULES
  // =======================================================

  const mediumMatches =
    getMediumMatches(
      normalized
    );


  if (
    mediumMatches.length
  ) {

    /*
     * If the message is clearly discussing a movie,
     * game, book, news report, history, etc., do not
     * flag the weapon terminology.
     */

    if (
      strongBenign ||
      hasBenignContext(
        normalized
      )
    ) {
      return {
        flagged: false,

        level: "NONE",

        category: "",

        reason: "",

        score: 0,
      };
    }


    const strongest =
      getStrongestRule(
        mediumMatches
      );


    return {
      flagged: true,

      level:
        strongest.level,

      category:
        strongest.category,

      reason:
        strongest.reason,

      score:
        strongest.score,
    };
  }


  // =======================================================
  // STEP 5
  // LOW-RISK RULES
  // =======================================================

  const lowMatches =
    getLowMatches(
      normalized
    );


  if (
    lowMatches.length
  ) {

    /*
     * Educational / historical / media discussions
     * should not generate a warning merely because
     * they contain words like "war", "violence",
     * or "terrorism".
     */

    if (
      hasBenignContext(
        normalized
      )
    ) {
      return {
        flagged: false,

        level: "NONE",

        category: "",

        reason: "",

        score: 0,
      };
    }


    const strongest =
      getStrongestRule(
        lowMatches
      );


    return {
      flagged: true,

      level:
        strongest.level,

      category:
        strongest.category,

      reason:
        strongest.reason,

      score:
        strongest.score,
    };
  }


  // =======================================================
  // STEP 6
  // NO MATCH
  // =======================================================

  return {
    flagged: false,

    level: "NONE",

    category: "",

    reason: "",

    score: 0,
  };
}


// =========================================================
// GET MODERATION RULES
// =========================================================

export function getModerationRules() {
  return RULES;
}