import Foundation
import MinerCore

setvbuf(stdout, nil, _IOLBF, 0)
exit(runCommandLine(Array(CommandLine.arguments.dropFirst())))
