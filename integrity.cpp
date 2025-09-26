

#include <iostream>
#include "integ.h"
int main() {
    using namespace AdvancedIntegrityCheck;

    if (!PerformComprehensiveCheck()) {
        ExitProcess(1);
    }

    RunProtectedApplication();

    return 0;
}