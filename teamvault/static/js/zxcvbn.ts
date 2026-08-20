import type {Match, Matcher, MatchEstimated, MatchExtended, MatchOptions, Options,} from '@zxcvbn-ts/core'
import {MatcherBaseClass, ZxcvbnFactory} from '@zxcvbn-ts/core'
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common'
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en'


const minLengthMatcher: Matcher = {
    Matching: class MatchMinLength extends MatcherBaseClass {
        minLength = 12  // TODO: Make this configurable via settings

        match({password}: MatchOptions) {
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
    feedback(options: Options, match: MatchEstimated, isSoleMatch?: boolean) {
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
    const factory = new ZxcvbnFactory({
        translations: zxcvbnEnPackage.translations,
        graphs: zxcvbnCommonPackage.adjacencyGraphs,
        dictionary: {
            ...zxcvbnCommonPackage.dictionary,
            ...zxcvbnEnPackage.dictionary,
        },
    }, {minLength: minLengthMatcher})
    return (password: string) => factory.check(password)
}
