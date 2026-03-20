/// 2-18-26 Created by SFP Sr.
/// 3-14-26 Modify for Leaf

import Vapor
import Leaf

public func configure(_ app: Application) throws {
    app.views.use(.leaf)

    app.middleware.use(FileMiddleware(publicDirectory: app.directory.publicDirectory))

    try routes(app)
}
