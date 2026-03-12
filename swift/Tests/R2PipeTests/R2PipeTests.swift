import XCTest
@testable import R2Pipe

final class R2PipeTests: XCTestCase {
    private func makePipe(_ target: String = "/bin/ls") throws -> R2Pipe {
        guard let pipe = R2Pipe(target) else {
            throw XCTSkip("Failed to open \(target) with r2pipe")
        }
        return pipe
    }

    private func trimmed(_ value: String?) -> String? {
        value?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func testCmdSyncSpawnEchoesCommandOutput() throws {
        let pipe = try makePipe()
        XCTAssertEqual(trimmed(pipe.cmdSync("?e hello-swift")), "hello-swift")
    }

    func testCmdjSyncParsesJsonOutput() throws {
        let pipe = try makePipe()
        let info = pipe.cmdjSync("ij")
        let core = info?["core"] as? NSDictionary
        XCTAssertEqual(core?["file"] as? String, "/bin/ls")
    }

    func testAsyncCallbacksPreserveCommandOrder() throws {
        let pipe = try makePipe()
        let first = expectation(description: "first callback")
        let second = expectation(description: "second callback")

        var firstResult: String?
        var secondResult: String?

        XCTAssertTrue(pipe.cmd("?e first") { result in
            firstResult = self.trimmed(result)
            first.fulfill()
        })
        XCTAssertTrue(pipe.cmd("?e second") { result in
            secondResult = self.trimmed(result)
            second.fulfill()
        })

        wait(for: [first, second], timeout: 5)
        XCTAssertEqual(firstResult, "first")
        XCTAssertEqual(secondResult, "second")
    }
}
