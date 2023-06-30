pipeline {
    agent any
    environment {
	PARAM1 = credentials('netboxtoken')
	PARAM2 = credentials('tokenpywire')
    }
    stages {
        stage('Intsall Packages') {
            steps {
		echo "Intsall Packages"
            }
        }
        stage('Test') {
            steps {
                echo 'testing'
                bat 'python jenkins.py ${PARAM1} ${PARAM2}'

            }
        }
    }
}
