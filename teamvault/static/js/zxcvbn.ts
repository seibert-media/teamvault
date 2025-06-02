import {zxcvbn, zxcvbnOptions} from '@zxcvbn-ts/core'
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common'
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en'
import {
    MatchEstimated,
    MatchExtended,
    Matcher,
    Match,
} from '@zxcvbn-ts/core/dist/types'


const minLengthMatcher: Matcher = {
    Matching: class MatchMinLength {
        minLength = 12  // TODO: Make this configurable via settings

        match({password}: { password: string }) {
            const matches: Match[] = []
            if (password.length != 0 && password.length < this.minLength) {
                matches.push({
                    pattern: 'minLength',
                    token: password,
                    i: 0,
                    j: password.length - 1,
                })
            }
            return matches
        }
    },
    feedback(match: MatchEstimated, isSoleMatch: boolean) {
        return {
            warning: 'Your password is not long enough',
            suggestions: [],
        }
    },
    scoring(match: MatchExtended) {
        // The length of the password is multiplied by 10 to create a higher score the more characters are added.
        return match.token.length * 10
    },
}


export function initZxcvbn() {
    zxcvbnOptions.addMatcher('minLength', minLengthMatcher)
    zxcvbnOptions.setOptions({
        translations: zxcvbnEnPackage.translations,
        graphs: zxcvbnCommonPackage.adjacencyGraphs,
        dictionary: {
            ...zxcvbnCommonPackage.dictionary,
            ...zxcvbnEnPackage.dictionary,
        },
    })
    return zxcvbn
}
