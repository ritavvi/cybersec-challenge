import ActivityKit

struct WalletAuthActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        var status: String
    }

    var title: String
}
