pipeline {
    agent any
    environment {
	PARAM3 = credentials('netboxtoken')
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
                bat 'python jenkins.py ${PARAM3}'

            }
        }
    }
}
